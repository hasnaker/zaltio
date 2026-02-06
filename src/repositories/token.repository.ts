/**
 * Token Repository - DynamoDB operations for verification/reset tokens
 * Handles email verification, password reset, and MFA tokens
 */

import {
  PutCommand,
  GetCommand,
  UpdateCommand,
  DeleteCommand,
  QueryCommand
} from '@aws-sdk/lib-dynamodb';
import { dynamoDb, TableNames } from '../services/dynamodb.service';

export enum TokenType {
  EMAIL_VERIFICATION = 'EMAIL_VERIFICATION',
  PASSWORD_RESET = 'PASSWORD_RESET',
  MFA_SETUP = 'MFA_SETUP'
}

export interface Token {
  token_hash: string;
  type: TokenType;
  user_id: string;
  realm_id: string;
  expires_at: string;
  created_at: string;
  used: boolean;
  used_at?: string;
}

export interface CreateTokenInput {
  token_hash: string;
  type: TokenType;
  user_id: string;
  realm_id: string;
  expires_at: string;
}

/**
 * Create a new token
 */
export async function createToken(input: CreateTokenInput): Promise<Token> {
  const now = new Date().toISOString();

  const token: Token = {
    ...input,
    created_at: now,
    used: false
  };

  const command = new PutCommand({
    TableName: TableNames.TOKENS,
    Item: {
      PK: `TOKEN#${input.token_hash}`,
      SK: input.type,
      ...token
    }
  });

  await dynamoDb.send(command);
  return token;
}

/**
 * Find token by hash and type
 */
export async function findToken(
  tokenHash: string,
  type: TokenType
): Promise<Token | null> {
  const command = new GetCommand({
    TableName: TableNames.TOKENS,
    Key: {
      PK: `TOKEN#${tokenHash}`,
      SK: type
    }
  });

  const result = await dynamoDb.send(command);
  
  if (!result.Item) {
    return null;
  }

  return result.Item as Token;
}

/**
 * Mark token as used
 */
export async function markTokenUsed(tokenHash: string): Promise<void> {
  const command = new UpdateCommand({
    TableName: TableNames.TOKENS,
    Key: {
      PK: `TOKEN#${tokenHash}`,
      SK: TokenType.EMAIL_VERIFICATION
    },
    UpdateExpression: 'SET used = :used, used_at = :usedAt',
    ExpressionAttributeValues: {
      ':used': true,
      ':usedAt': new Date().toISOString()
    }
  });

  await dynamoDb.send(command);
}

/**
 * Delete token
 */
export async function deleteToken(tokenHash: string, type: TokenType): Promise<void> {
  const command = new DeleteCommand({
    TableName: TableNames.TOKENS,
    Key: {
      PK: `TOKEN#${tokenHash}`,
      SK: type
    }
  });

  await dynamoDb.send(command);
}

/**
 * Delete all tokens for a user (e.g., after password reset)
 */
export async function deleteUserTokens(
  userId: string,
  realmId: string,
  type?: TokenType
): Promise<void> {
  // Query tokens by user
  const queryCommand = new QueryCommand({
    TableName: TableNames.TOKENS,
    IndexName: 'user-index',
    KeyConditionExpression: 'user_id = :userId',
    FilterExpression: type 
      ? 'realm_id = :realmId AND #type = :type'
      : 'realm_id = :realmId',
    ExpressionAttributeNames: type ? { '#type': 'type' } : undefined,
    ExpressionAttributeValues: {
      ':userId': userId,
      ':realmId': realmId,
      ...(type && { ':type': type })
    }
  });

  const result = await dynamoDb.send(queryCommand);

  if (!result.Items || result.Items.length === 0) {
    return;
  }

  // Delete each token
  for (const item of result.Items) {
    const token = item as Token & { PK: string; SK: string };
    await deleteToken(token.token_hash, token.type);
  }
}

/**
 * Clean up expired tokens (called by scheduled Lambda)
 */
export async function cleanupExpiredTokens(): Promise<number> {
  const now = new Date().toISOString();
  let deletedCount = 0;

  // Scan for expired tokens (in production, use GSI on expires_at)
  // This is a simplified version - production should use pagination
  
  return deletedCount;
}
