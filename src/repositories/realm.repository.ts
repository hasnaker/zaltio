/**
 * Realm Repository - DynamoDB operations for realms
 * Validates: Requirements 1.1, 1.3, 1.5 (multi-tenant architecture)
 */

import {
  GetCommand,
  PutCommand,
  DeleteCommand,
  QueryCommand,
  ScanCommand,
  UpdateCommand
} from '@aws-sdk/lib-dynamodb';
import { dynamoDb, TableNames } from '../services/dynamodb.service';
import {
  Realm,
  RealmSettings,
  CreateRealmInput,
  DEFAULT_REALM_SETTINGS,
  AuthProvider
} from '../models/realm.model';
import * as crypto from 'crypto';

// Use crypto.randomUUID() instead of uuid package for ESM compatibility
const uuidv4 = () => crypto.randomUUID();

/**
 * Get realm by ID
 */
export async function findRealmById(realmId: string): Promise<Realm | null> {
  const command = new GetCommand({
    TableName: TableNames.REALMS,
    Key: {
      pk: `REALM#${realmId}`,
      sk: `REALM#${realmId}`
    }
  });

  const result = await dynamoDb.send(command);
  
  if (!result.Item) {
    return null;
  }

  // Map DynamoDB item to Realm interface
  const item = result.Item;
  return {
    id: item.id || realmId,
    name: item.name,
    domain: item.domain,
    settings: item.settings || DEFAULT_REALM_SETTINGS,
    auth_providers: item.auth_providers || [],
    created_at: item.createdAt || item.created_at,
    updated_at: item.updatedAt || item.updated_at
  } as Realm;
}

/**
 * Get realm settings (for password policy, etc.)
 */
export async function getRealmSettings(realmId: string): Promise<RealmSettings> {
  const realm = await findRealmById(realmId);
  
  if (!realm) {
    // Return default settings if realm not found
    return DEFAULT_REALM_SETTINGS;
  }

  return realm.settings;
}

/**
 * Create a new realm with isolated configuration
 * Validates: Requirements 1.1 (dedicated realm creation)
 */
export async function createRealm(input: CreateRealmInput): Promise<Realm> {
  const realmId = input.name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '');
  
  const now = new Date().toISOString();

  // Merge provided settings with defaults
  const settings: RealmSettings = {
    ...DEFAULT_REALM_SETTINGS,
    ...input.settings,
    password_policy: {
      ...DEFAULT_REALM_SETTINGS.password_policy,
      ...input.settings?.password_policy
    }
  };

  // Default auth provider if none provided
  const authProviders: AuthProvider[] = input.auth_providers || [
    {
      type: 'email_password',
      enabled: true,
      config: {}
    }
  ];

  const realm: Realm = {
    id: realmId,
    name: input.name,
    domain: input.domain,
    settings,
    auth_providers: authProviders,
    created_at: now,
    updated_at: now
  };

  // DynamoDB item with pk/sk keys
  const item = {
    pk: `REALM#${realmId}`,
    sk: `REALM#${realmId}`,
    ...realm
  };

  const command = new PutCommand({
    TableName: TableNames.REALMS,
    Item: item,
    ConditionExpression: 'attribute_not_exists(pk)'
  });

  await dynamoDb.send(command);

  return realm;
}

/**
 * Update realm configuration
 * Validates: Requirements 1.3 (realm-specific configuration updates)
 */
export async function updateRealm(
  realmId: string,
  updates: {
    name?: string;
    domain?: string;
    settings?: Partial<RealmSettings>;
    auth_providers?: AuthProvider[];
  }
): Promise<Realm | null> {
  const existingRealm = await findRealmById(realmId);
  if (!existingRealm) {
    return null;
  }

  const now = new Date().toISOString();
  
  // Build update expression dynamically
  const updateExpressions: string[] = ['#updated_at = :updated_at'];
  const expressionAttributeNames: Record<string, string> = {
    '#updated_at': 'updated_at'
  };
  const expressionAttributeValues: Record<string, unknown> = {
    ':updated_at': now
  };

  if (updates.name !== undefined) {
    updateExpressions.push('#name = :name');
    expressionAttributeNames['#name'] = 'name';
    expressionAttributeValues[':name'] = updates.name;
  }

  if (updates.domain !== undefined) {
    updateExpressions.push('#domain = :domain');
    expressionAttributeNames['#domain'] = 'domain';
    expressionAttributeValues[':domain'] = updates.domain;
  }

  if (updates.settings !== undefined) {
    // Merge with existing settings
    const mergedSettings: RealmSettings = {
      ...existingRealm.settings,
      ...updates.settings,
      password_policy: {
        ...existingRealm.settings.password_policy,
        ...updates.settings.password_policy
      }
    };
    updateExpressions.push('#settings = :settings');
    expressionAttributeNames['#settings'] = 'settings';
    expressionAttributeValues[':settings'] = mergedSettings;
  }

  if (updates.auth_providers !== undefined) {
    updateExpressions.push('#auth_providers = :auth_providers');
    expressionAttributeNames['#auth_providers'] = 'auth_providers';
    expressionAttributeValues[':auth_providers'] = updates.auth_providers;
  }

  const command = new UpdateCommand({
    TableName: TableNames.REALMS,
    Key: {
      pk: `REALM#${realmId}`,
      sk: `REALM#${realmId}`
    },
    UpdateExpression: `SET ${updateExpressions.join(', ')}`,
    ExpressionAttributeNames: expressionAttributeNames,
    ExpressionAttributeValues: expressionAttributeValues,
    ReturnValues: 'ALL_NEW'
  });

  const result = await dynamoDb.send(command);
  
  if (!result.Attributes) {
    return null;
  }

  const item = result.Attributes;
  return {
    id: item.id || item.pk,
    name: item.name,
    domain: item.domain,
    settings: item.settings,
    auth_providers: item.auth_providers,
    created_at: item.created_at,
    updated_at: item.updated_at
  } as Realm;
}

/**
 * Delete realm record
 * Note: This only deletes the realm configuration, not associated data
 * Use deleteRealmWithCleanup for complete cleanup
 */
export async function deleteRealm(realmId: string): Promise<boolean> {
  const command = new DeleteCommand({
    TableName: TableNames.REALMS,
    Key: {
      pk: `REALM#${realmId}`,
      sk: `REALM#${realmId}`
    }
  });

  try {
    await dynamoDb.send(command);
    return true;
  } catch {
    return false;
  }
}

/**
 * List all realms
 */
export async function listRealms(): Promise<Realm[]> {
  const command = new ScanCommand({
    TableName: TableNames.REALMS,
    FilterExpression: 'begins_with(pk, :prefix)',
    ExpressionAttributeValues: {
      ':prefix': 'REALM#'
    }
  });

  const result = await dynamoDb.send(command);
  
  if (!result.Items) {
    return [];
  }

  return result.Items.map((item) => ({
    id: item.id,
    name: item.name,
    domain: item.domain,
    settings: item.settings || DEFAULT_REALM_SETTINGS,
    auth_providers: item.auth_providers || [],
    created_at: item.created_at,
    updated_at: item.updated_at
  })) as Realm[];
}

/**
 * Count realms (for limit checking)
 */
export async function countRealms(): Promise<number> {
  const command = new ScanCommand({
    TableName: TableNames.REALMS,
    Select: 'COUNT'
  });

  const result = await dynamoDb.send(command);
  return result.Count || 0;
}

/**
 * Check if realm exists by name (for duplicate prevention)
 */
export async function realmExistsByName(name: string): Promise<boolean> {
  const realmId = name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '');
  
  const realm = await findRealmById(realmId);
  return realm !== null;
}
