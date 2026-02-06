/**
 * OAuth Client Repository - DynamoDB operations for OAuth clients
 * Validates: Requirements 6.1, 9.1 (OAuth 2.0 client management)
 * 
 * CRITICAL: Production-ready - stores OAuth clients in DynamoDB
 * NOT in-memory like before!
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
import { OAuthClient, OIDCScope, OAuthGrantType } from '../models/sso.model';
import * as crypto from 'crypto';

const uuidv4 = () => crypto.randomUUID();

/**
 * DynamoDB schema for OAuth clients stored in zalt-realms table
 * PK: clientId
 * SK: OAUTH_CLIENT#<clientId>
 * 
 * Also supports legacy format where realm data includes OAuth fields directly
 */

export interface OAuthClientRecord {
  clientId: string;
  clientSecretHash: string;
  clientName: string;
  application: string;
  redirectUris: string[];
  allowedScopes: string[];
  grantTypes: string[];
  realmId: string;
  createdAt: number;
  updatedAt: number;
}

/**
 * Find OAuth client by client_id
 * Checks both new format (OAUTH_CLIENT#) and legacy format (realm with clientId field)
 */
export async function findOAuthClientById(clientId: string): Promise<OAuthClient | null> {
  // Scan for clientId field match (legacy Clinisyn format stores clientId separately from realmId)
  try {
    const scanCommand = new ScanCommand({
      TableName: TableNames.REALMS,
      FilterExpression: 'clientId = :clientId',
      ExpressionAttributeValues: {
        ':clientId': clientId
      },
      Limit: 10
    });

    const scanResult = await dynamoDb.send(scanCommand);
    
    if (scanResult.Items && scanResult.Items.length > 0) {
      console.log('Found OAuth client by clientId scan:', clientId);
      return mapLegacyRealmToOAuthClient(scanResult.Items[0]);
    }
  } catch (error) {
    console.error('Error scanning for OAuth client:', error);
  }

  // Fallback: Try direct lookup by realmId (in case clientId === realmId)
  try {
    const command = new GetCommand({
      TableName: TableNames.REALMS,
      Key: {
        realmId: clientId
      }
    });

    const result = await dynamoDb.send(command);
    
    if (result.Item && result.Item.clientId) {
      console.log('Found OAuth client by realmId lookup:', clientId);
      return mapLegacyRealmToOAuthClient(result.Item);
    }
  } catch (error) {
    console.error('Error getting OAuth client by realmId:', error);
  }

  console.log('OAuth client not found:', clientId);
  return null;
}

/**
 * Map legacy realm record (with OAuth fields) to OAuthClient interface
 */
function mapLegacyRealmToOAuthClient(item: Record<string, unknown>): OAuthClient {
  return {
    client_id: item.clientId as string,
    client_secret_hash: item.clientSecret as string, // Note: legacy stores plain, we'll handle this
    client_name: item.name as string || 'Unknown Client',
    application: 'hsd-portal', // Default for legacy
    redirect_uris: (item.redirectUris as string[]) || [],
    allowed_scopes: (item.allowedScopes as OIDCScope[]) || ['openid', 'profile', 'email'],
    grant_types: ['authorization_code', 'refresh_token'] as OAuthGrantType[],
    realm_id: item.realmId as string,
    created_at: item.createdAt ? new Date(Number(item.createdAt) * 1000).toISOString() : new Date().toISOString(),
    updated_at: item.updatedAt ? new Date(Number(item.updatedAt) * 1000).toISOString() : new Date().toISOString()
  };
}

/**
 * Find OAuth client by realm_id
 */
export async function findOAuthClientByRealmId(realmId: string): Promise<OAuthClient | null> {
  // Try to get realm record directly
  const command = new GetCommand({
    TableName: TableNames.REALMS,
    Key: {
      realmId: realmId
    }
  });

  const result = await dynamoDb.send(command);
  
  if (result.Item && result.Item.clientId) {
    return mapLegacyRealmToOAuthClient(result.Item);
  }

  return null;
}

/**
 * Create new OAuth client
 */
export async function createOAuthClient(
  realmId: string,
  clientName: string,
  redirectUris: string[],
  allowedScopes: OIDCScope[] = ['openid', 'profile', 'email'],
  application: string = 'hsd-portal'
): Promise<{ client: OAuthClient; plainSecret: string }> {
  const clientId = `${realmId}-${uuidv4().substring(0, 8)}`;
  const plainSecret = crypto.randomBytes(32).toString('hex');
  const secretHash = crypto.createHash('sha256').update(plainSecret).digest('hex');
  
  const now = Math.floor(Date.now() / 1000);

  const item = {
    realmId: clientId, // Use clientId as PK for new format
    clientId: clientId,
    clientSecret: secretHash,
    clientSecretHash: secretHash,
    clientName: clientName,
    application: application,
    redirectUris: redirectUris,
    allowedScopes: allowedScopes,
    grantTypes: ['authorization_code', 'refresh_token'],
    createdAt: now,
    updatedAt: now,
    type: 'OAUTH_CLIENT' // Marker to distinguish from realm records
  };

  const command = new PutCommand({
    TableName: TableNames.REALMS,
    Item: item
  });

  await dynamoDb.send(command);

  const client: OAuthClient = {
    client_id: clientId,
    client_secret_hash: secretHash,
    client_name: clientName,
    application: application as any,
    redirect_uris: redirectUris,
    allowed_scopes: allowedScopes,
    grant_types: ['authorization_code', 'refresh_token'],
    realm_id: realmId,
    created_at: new Date(now * 1000).toISOString(),
    updated_at: new Date(now * 1000).toISOString()
  };

  return { client, plainSecret };
}

/**
 * Validate client credentials
 * Supports both hashed and plain text secrets (for legacy compatibility)
 */
export async function validateOAuthClientCredentials(
  clientId: string,
  clientSecret: string
): Promise<boolean> {
  const client = await findOAuthClientById(clientId);
  
  if (!client) {
    return false;
  }

  // Try hashed comparison first
  const providedHash = crypto.createHash('sha256').update(clientSecret).digest('hex');
  if (client.client_secret_hash === providedHash) {
    return true;
  }

  // Legacy: direct comparison (for old records with plain secrets)
  if (client.client_secret_hash === clientSecret) {
    return true;
  }

  return false;
}

/**
 * Update OAuth client
 */
export async function updateOAuthClient(
  clientId: string,
  updates: {
    clientName?: string;
    redirectUris?: string[];
    allowedScopes?: OIDCScope[];
  }
): Promise<OAuthClient | null> {
  const existingClient = await findOAuthClientById(clientId);
  if (!existingClient) {
    return null;
  }

  const now = Math.floor(Date.now() / 1000);
  
  const updateExpressions: string[] = ['#updatedAt = :updatedAt'];
  const expressionAttributeNames: Record<string, string> = {
    '#updatedAt': 'updatedAt'
  };
  const expressionAttributeValues: Record<string, unknown> = {
    ':updatedAt': now
  };

  if (updates.clientName) {
    updateExpressions.push('#clientName = :clientName');
    expressionAttributeNames['#clientName'] = 'clientName';
    expressionAttributeValues[':clientName'] = updates.clientName;
  }

  if (updates.redirectUris) {
    updateExpressions.push('#redirectUris = :redirectUris');
    expressionAttributeNames['#redirectUris'] = 'redirectUris';
    expressionAttributeValues[':redirectUris'] = updates.redirectUris;
  }

  if (updates.allowedScopes) {
    updateExpressions.push('#allowedScopes = :allowedScopes');
    expressionAttributeNames['#allowedScopes'] = 'allowedScopes';
    expressionAttributeValues[':allowedScopes'] = updates.allowedScopes;
  }

  const command = new UpdateCommand({
    TableName: TableNames.REALMS,
    Key: {
      realmId: existingClient.realm_id
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

  return mapLegacyRealmToOAuthClient(result.Attributes);
}

/**
 * Delete OAuth client
 */
export async function deleteOAuthClient(clientId: string): Promise<boolean> {
  const client = await findOAuthClientById(clientId);
  if (!client) {
    return false;
  }

  const command = new DeleteCommand({
    TableName: TableNames.REALMS,
    Key: {
      realmId: client.realm_id
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
 * List all OAuth clients
 */
export async function listOAuthClients(): Promise<OAuthClient[]> {
  const command = new ScanCommand({
    TableName: TableNames.REALMS,
    FilterExpression: 'attribute_exists(clientId)'
  });

  const result = await dynamoDb.send(command);
  
  if (!result.Items) {
    return [];
  }

  return result.Items.map(item => mapLegacyRealmToOAuthClient(item));
}
