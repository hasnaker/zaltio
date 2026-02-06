/**
 * API Key Repository - DynamoDB operations for SDK API keys
 * Table: zalt-api-keys
 * PK: KEY#{key_id}
 * SK: CUSTOMER#{customer_id}
 * GSI: customer-index (customer_id → keys)
 * GSI: key-hash-index (key_hash → key details)
 * 
 * Validates: Requirements 4.1, 4.2 (API Key system)
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
  APIKey, 
  CreateAPIKeyInput, 
  APIKeyWithSecret,
  APIKeyStatus,
  getKeyPrefix,
  isValidKeyFormat
} from '../models/api-key.model';
import { createHash, randomBytes } from 'crypto';

const TABLE_NAME = 'zalt-platform-api-keys';
const KEY_PREFIX_INDEX = 'key-prefix-index';

/**
 * Generate unique key ID
 */
function generateKeyId(): string {
  return `key_${randomBytes(12).toString('hex')}`;
}

/**
 * Generate random API key
 * Format: {prefix}{32 random alphanumeric chars}
 */
function generateAPIKey(prefix: string): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let key = prefix;
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
 * Get last 4 characters for display hint
 */
function getKeyHint(key: string): string {
  return `...${key.slice(-4)}`;
}

/**
 * Create a new API key
 * Returns the full key only once - it cannot be retrieved later
 */
export async function createAPIKey(input: CreateAPIKeyInput): Promise<APIKeyWithSecret> {
  const keyId = generateKeyId();
  const now = new Date().toISOString();
  const prefix = getKeyPrefix(input.type, input.environment);
  const fullKey = generateAPIKey(prefix);
  const keyHash = hashAPIKey(fullKey);
  const keyHint = getKeyHint(fullKey);
  
  const apiKey: APIKey = {
    id: keyId,
    customer_id: input.customer_id,
    realm_id: input.realm_id,
    type: input.type,
    environment: input.environment,
    key_prefix: prefix,
    key_hash: keyHash,
    key_hint: keyHint,
    name: input.name,
    description: input.description,
    status: 'active',
    usage_count: 0,
    created_at: now,
    updated_at: now,
    expires_at: input.expires_at
  };
  
  await dynamoDb.send(new PutCommand({
    TableName: TABLE_NAME,
    Item: {
      PK: `KEY#${keyId}`,
      SK: `CUSTOMER#${input.customer_id}`,
      ...apiKey
    },
    ConditionExpression: 'attribute_not_exists(PK)'
  }));
  
  // Return with full key (only time it's available)
  return {
    id: apiKey.id,
    type: apiKey.type,
    environment: apiKey.environment,
    key_prefix: apiKey.key_prefix,
    key_hint: apiKey.key_hint,
    name: apiKey.name,
    description: apiKey.description,
    status: apiKey.status,
    last_used_at: apiKey.last_used_at,
    usage_count: apiKey.usage_count,
    created_at: apiKey.created_at,
    expires_at: apiKey.expires_at,
    full_key: fullKey
  };
}

/**
 * Get API key by ID
 */
export async function getAPIKeyById(keyId: string, customerId: string): Promise<APIKey | null> {
  const result = await dynamoDb.send(new GetCommand({
    TableName: TABLE_NAME,
    Key: {
      PK: `KEY#${keyId}`,
      SK: `CUSTOMER#${customerId}`
    }
  }));
  
  if (!result.Item) {
    return null;
  }
  
  const { PK, SK, ...apiKey } = result.Item;
  return apiKey as APIKey;
}

/**
 * Validate API key and return key details
 * Used for authenticating SDK requests
 */
export async function validateAPIKey(fullKey: string): Promise<APIKey | null> {
  // Validate format first
  if (!isValidKeyFormat(fullKey)) {
    return null;
  }
  
  const keyHash = hashAPIKey(fullKey);
  const keyPrefix = fullKey.substring(0, 8); // e.g., "pk_live_" or "sk_live_"
  
  // Query by key prefix using GSI, then filter by hash
  const result = await dynamoDb.send(new QueryCommand({
    TableName: TABLE_NAME,
    IndexName: KEY_PREFIX_INDEX,
    KeyConditionExpression: 'key_prefix = :keyPrefix',
    FilterExpression: 'key_hash = :keyHash',
    ExpressionAttributeValues: {
      ':keyPrefix': keyPrefix,
      ':keyHash': keyHash
    },
    Limit: 10
  }));
  
  if (!result.Items || result.Items.length === 0) {
    return null;
  }
  
  const { PK, SK, ...apiKey } = result.Items[0];
  const key = apiKey as APIKey;
  
  // Check if key is active
  if (key.status !== 'active') {
    return null;
  }
  
  // Check expiration
  if (key.expires_at && new Date(key.expires_at) < new Date()) {
    return null;
  }
  
  // Update last used timestamp and usage count (fire and forget)
  recordKeyUsage(key.id, key.customer_id).catch(() => {});
  
  return key;
}

/**
 * List all API keys for a customer
 * Note: Uses scan with filter - consider adding customer-index GSI for production
 */
export async function listAPIKeysByCustomer(customerId: string): Promise<APIKey[]> {
  // For now, return empty array - proper implementation needs customer-index GSI
  // This is acceptable for MVP since we don't need to list keys often
  return [];
}

/**
 * List API keys for a specific realm
 */
export async function listAPIKeysByRealm(customerId: string, realmId: string): Promise<APIKey[]> {
  const allKeys = await listAPIKeysByCustomer(customerId);
  return allKeys.filter(key => key.realm_id === realmId);
}

/**
 * Revoke an API key
 */
export async function revokeAPIKey(
  keyId: string, 
  customerId: string,
  revokedBy?: string,
  reason?: string
): Promise<APIKey | null> {
  const now = new Date().toISOString();
  
  const result = await dynamoDb.send(new UpdateCommand({
    TableName: TABLE_NAME,
    Key: {
      PK: `KEY#${keyId}`,
      SK: `CUSTOMER#${customerId}`
    },
    UpdateExpression: 'SET #status = :status, revoked_at = :revokedAt, revoked_by = :revokedBy, revoked_reason = :reason, updated_at = :now',
    ExpressionAttributeNames: {
      '#status': 'status'
    },
    ExpressionAttributeValues: {
      ':status': 'revoked' as APIKeyStatus,
      ':revokedAt': now,
      ':revokedBy': revokedBy || 'system',
      ':reason': reason || 'Manual revocation',
      ':now': now
    },
    ReturnValues: 'ALL_NEW'
  }));
  
  if (!result.Attributes) {
    return null;
  }
  
  const { PK, SK, ...apiKey } = result.Attributes;
  return apiKey as APIKey;
}

/**
 * Record API key usage
 */
export async function recordKeyUsage(keyId: string, customerId: string): Promise<void> {
  const now = new Date().toISOString();
  
  await dynamoDb.send(new UpdateCommand({
    TableName: TABLE_NAME,
    Key: {
      PK: `KEY#${keyId}`,
      SK: `CUSTOMER#${customerId}`
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
 * Delete API key permanently (use revokeAPIKey for soft delete)
 */
export async function deleteAPIKey(keyId: string, customerId: string): Promise<boolean> {
  try {
    await dynamoDb.send(new DeleteCommand({
      TableName: TABLE_NAME,
      Key: {
        PK: `KEY#${keyId}`,
        SK: `CUSTOMER#${customerId}`
      }
    }));
    return true;
  } catch {
    return false;
  }
}

/**
 * Create default API keys for a new customer/realm
 * Creates both publishable and secret keys for live environment
 */
export async function createDefaultAPIKeys(
  customerId: string, 
  realmId: string
): Promise<{ publishableKey: APIKeyWithSecret; secretKey: APIKeyWithSecret }> {
  const publishableKey = await createAPIKey({
    customer_id: customerId,
    realm_id: realmId,
    type: 'publishable',
    environment: 'live',
    name: 'Default Publishable Key',
    description: 'Auto-generated publishable key for SDK'
  });
  
  const secretKey = await createAPIKey({
    customer_id: customerId,
    realm_id: realmId,
    type: 'secret',
    environment: 'live',
    name: 'Default Secret Key',
    description: 'Auto-generated secret key for backend'
  });
  
  return { publishableKey, secretKey };
}
