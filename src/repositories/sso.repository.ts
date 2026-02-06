/**
 * SSO Repository - DynamoDB operations for SSO sessions and OAuth clients
 * Validates: Requirements 6.2, 6.4 (SSO, backward compatibility)
 */

import {
  PutCommand,
  GetCommand,
  DeleteCommand,
  QueryCommand,
  UpdateCommand
} from '@aws-sdk/lib-dynamodb';
import { dynamoDb, TableNames } from '../services/dynamodb.service';
import {
  SSOSession,
  AuthorizationCode,
  OAuthClient,
  HSDApplication
} from '../models/sso.model';
import * as crypto from 'crypto';

// Use crypto.randomUUID() instead of uuid package for ESM compatibility
const uuidv4 = () => crypto.randomUUID();

const SSO_SESSION_TTL = 8 * 60 * 60; // 8 hours in seconds
const AUTH_CODE_TTL = 10 * 60; // 10 minutes in seconds

/**
 * Create SSO session in DynamoDB
 * Validates: Requirements 6.2 (cross-application session sharing)
 */
export async function createSSOSessionInDB(
  userId: string,
  realmId: string,
  primarySessionId: string,
  initialApplication: HSDApplication
): Promise<SSOSession> {
  const sessionId = uuidv4();
  const now = new Date();
  const expiresAt = new Date(now.getTime() + SSO_SESSION_TTL * 1000);
  const ttl = Math.floor(expiresAt.getTime() / 1000);

  const session: SSOSession & { pk: string; sk: string; ttl: number } = {
    pk: `SSO#${sessionId}`,
    sk: `SESSION#${realmId}#${userId}`,
    id: sessionId,
    user_id: userId,
    realm_id: realmId,
    authenticated_applications: [initialApplication],
    primary_session_id: primarySessionId,
    created_at: now.toISOString(),
    expires_at: expiresAt.toISOString(),
    last_activity: now.toISOString(),
    ttl
  };

  const command = new PutCommand({
    TableName: TableNames.SESSIONS,
    Item: session
  });

  await dynamoDb.send(command);

  const { pk, sk, ttl: _, ...sessionResponse } = session;
  return sessionResponse as SSOSession;
}

/**
 * Get SSO session by ID
 */
export async function getSSOSessionFromDB(sessionId: string): Promise<SSOSession | null> {
  const command = new QueryCommand({
    TableName: TableNames.SESSIONS,
    KeyConditionExpression: 'pk = :pk',
    ExpressionAttributeValues: {
      ':pk': `SSO#${sessionId}`
    }
  });

  const result = await dynamoDb.send(command);
  
  if (!result.Items || result.Items.length === 0) {
    return null;
  }

  const item = result.Items[0];
  
  // Check if expired
  if (new Date(item.expires_at as string) < new Date()) {
    return null;
  }

  return {
    id: item.id,
    user_id: item.user_id,
    realm_id: item.realm_id,
    authenticated_applications: item.authenticated_applications,
    primary_session_id: item.primary_session_id,
    created_at: item.created_at,
    expires_at: item.expires_at,
    last_activity: item.last_activity
  } as SSOSession;
}

/**
 * Add application to SSO session
 * Validates: Requirements 6.2 (cross-application session sharing)
 */
export async function addApplicationToSSOSessionInDB(
  sessionId: string,
  realmId: string,
  userId: string,
  application: HSDApplication
): Promise<SSOSession | null> {
  const session = await getSSOSessionFromDB(sessionId);
  if (!session) {
    return null;
  }

  // Add application if not already present
  const applications = session.authenticated_applications.includes(application)
    ? session.authenticated_applications
    : [...session.authenticated_applications, application];

  const command = new UpdateCommand({
    TableName: TableNames.SESSIONS,
    Key: {
      pk: `SSO#${sessionId}`,
      sk: `SESSION#${realmId}#${userId}`
    },
    UpdateExpression: 'SET authenticated_applications = :apps, last_activity = :lastActivity',
    ExpressionAttributeValues: {
      ':apps': applications,
      ':lastActivity': new Date().toISOString()
    },
    ReturnValues: 'ALL_NEW'
  });

  try {
    const result = await dynamoDb.send(command);
    if (!result.Attributes) {
      return null;
    }

    return {
      id: result.Attributes.id,
      user_id: result.Attributes.user_id,
      realm_id: result.Attributes.realm_id,
      authenticated_applications: result.Attributes.authenticated_applications,
      primary_session_id: result.Attributes.primary_session_id,
      created_at: result.Attributes.created_at,
      expires_at: result.Attributes.expires_at,
      last_activity: result.Attributes.last_activity
    } as SSOSession;
  } catch {
    return null;
  }
}

/**
 * Delete SSO session
 */
export async function deleteSSOSessionFromDB(
  sessionId: string,
  realmId: string,
  userId: string
): Promise<boolean> {
  const command = new DeleteCommand({
    TableName: TableNames.SESSIONS,
    Key: {
      pk: `SSO#${sessionId}`,
      sk: `SESSION#${realmId}#${userId}`
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
 * Get all SSO sessions for a user
 */
export async function getUserSSOSessions(
  realmId: string,
  userId: string
): Promise<SSOSession[]> {
  const command = new QueryCommand({
    TableName: TableNames.SESSIONS,
    IndexName: 'user-realm-index',
    KeyConditionExpression: 'realm_id = :realmId AND user_id = :userId',
    FilterExpression: 'begins_with(pk, :ssoPrefix)',
    ExpressionAttributeValues: {
      ':realmId': realmId,
      ':userId': userId,
      ':ssoPrefix': 'SSO#'
    }
  });

  const result = await dynamoDb.send(command);
  
  if (!result.Items || result.Items.length === 0) {
    return [];
  }

  const now = new Date();
  return result.Items
    .filter(item => new Date(item.expires_at as string) > now)
    .map(item => ({
      id: item.id,
      user_id: item.user_id,
      realm_id: item.realm_id,
      authenticated_applications: item.authenticated_applications,
      primary_session_id: item.primary_session_id,
      created_at: item.created_at,
      expires_at: item.expires_at,
      last_activity: item.last_activity
    })) as SSOSession[];
}

/**
 * Store authorization code
 */
export async function storeAuthorizationCode(
  code: AuthorizationCode
): Promise<void> {
  const ttl = Math.floor(new Date(code.expires_at).getTime() / 1000);

  const item = {
    pk: `AUTHCODE#${code.code}`,
    sk: `CLIENT#${code.client_id}`,
    ...code,
    ttl
  };

  const command = new PutCommand({
    TableName: TableNames.SESSIONS,
    Item: item
  });

  await dynamoDb.send(command);
}

/**
 * Get and delete authorization code (single use)
 */
export async function consumeAuthorizationCode(
  code: string
): Promise<AuthorizationCode | null> {
  const command = new QueryCommand({
    TableName: TableNames.SESSIONS,
    KeyConditionExpression: 'pk = :pk',
    ExpressionAttributeValues: {
      ':pk': `AUTHCODE#${code}`
    }
  });

  const result = await dynamoDb.send(command);
  
  if (!result.Items || result.Items.length === 0) {
    return null;
  }

  const item = result.Items[0];
  
  // Check if expired
  if (new Date(item.expires_at as string) < new Date()) {
    return null;
  }

  // Delete the code (single use)
  const deleteCommand = new DeleteCommand({
    TableName: TableNames.SESSIONS,
    Key: {
      pk: `AUTHCODE#${code}`,
      sk: item.sk
    }
  });

  await dynamoDb.send(deleteCommand);

  return {
    code: item.code,
    client_id: item.client_id,
    user_id: item.user_id,
    realm_id: item.realm_id,
    redirect_uri: item.redirect_uri,
    scope: item.scope,
    code_challenge: item.code_challenge,
    code_challenge_method: item.code_challenge_method,
    expires_at: item.expires_at,
    created_at: item.created_at
  } as AuthorizationCode;
}

/**
 * Store OAuth client registration
 */
export async function storeOAuthClient(client: OAuthClient): Promise<void> {
  const item = {
    pk: `CLIENT#${client.client_id}`,
    sk: `REALM#${client.realm_id}`,
    ...client
  };

  const command = new PutCommand({
    TableName: TableNames.REALMS,
    Item: item
  });

  await dynamoDb.send(command);
}

/**
 * Get OAuth client by ID
 */
export async function getOAuthClientFromDB(clientId: string): Promise<OAuthClient | null> {
  const command = new QueryCommand({
    TableName: TableNames.REALMS,
    KeyConditionExpression: 'pk = :pk',
    ExpressionAttributeValues: {
      ':pk': `CLIENT#${clientId}`
    }
  });

  const result = await dynamoDb.send(command);
  
  if (!result.Items || result.Items.length === 0) {
    return null;
  }

  const item = result.Items[0];
  return {
    client_id: item.client_id,
    client_secret_hash: item.client_secret_hash,
    client_name: item.client_name,
    application: item.application,
    redirect_uris: item.redirect_uris,
    allowed_scopes: item.allowed_scopes,
    grant_types: item.grant_types,
    realm_id: item.realm_id,
    created_at: item.created_at,
    updated_at: item.updated_at
  } as OAuthClient;
}

/**
 * Get all OAuth clients for a realm
 */
export async function getRealmOAuthClients(realmId: string): Promise<OAuthClient[]> {
  const command = new QueryCommand({
    TableName: TableNames.REALMS,
    IndexName: 'realm-index',
    KeyConditionExpression: 'realm_id = :realmId',
    FilterExpression: 'begins_with(pk, :clientPrefix)',
    ExpressionAttributeValues: {
      ':realmId': realmId,
      ':clientPrefix': 'CLIENT#'
    }
  });

  const result = await dynamoDb.send(command);
  
  if (!result.Items || result.Items.length === 0) {
    return [];
  }

  return result.Items.map(item => ({
    client_id: item.client_id,
    client_secret_hash: item.client_secret_hash,
    client_name: item.client_name,
    application: item.application,
    redirect_uris: item.redirect_uris,
    allowed_scopes: item.allowed_scopes,
    grant_types: item.grant_types,
    realm_id: item.realm_id,
    created_at: item.created_at,
    updated_at: item.updated_at
  })) as OAuthClient[];
}

/**
 * Delete OAuth client
 */
export async function deleteOAuthClient(
  clientId: string,
  realmId: string
): Promise<boolean> {
  const command = new DeleteCommand({
    TableName: TableNames.REALMS,
    Key: {
      pk: `CLIENT#${clientId}`,
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
 * Find SSO session by primary session ID
 * Validates: Requirements 6.2 (session linking)
 */
export async function findSSOSessionByPrimarySession(
  primarySessionId: string
): Promise<SSOSession | null> {
  const command = new QueryCommand({
    TableName: TableNames.SESSIONS,
    IndexName: 'primary-session-index',
    KeyConditionExpression: 'primary_session_id = :sessionId',
    ExpressionAttributeValues: {
      ':sessionId': primarySessionId
    }
  });

  const result = await dynamoDb.send(command);
  
  if (!result.Items || result.Items.length === 0) {
    return null;
  }

  const item = result.Items[0];
  
  // Check if expired
  if (new Date(item.expires_at as string) < new Date()) {
    return null;
  }

  return {
    id: item.id,
    user_id: item.user_id,
    realm_id: item.realm_id,
    authenticated_applications: item.authenticated_applications,
    primary_session_id: item.primary_session_id,
    created_at: item.created_at,
    expires_at: item.expires_at,
    last_activity: item.last_activity
  } as SSOSession;
}
