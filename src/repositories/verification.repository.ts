/**
 * Verification Code Repository
 * Stores email verification codes in DynamoDB with TTL
 * 
 * @security Codes are hashed before storage
 * @healthcare HIPAA compliant - no PHI stored
 */

import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { 
  DynamoDBDocumentClient, 
  PutCommand, 
  GetCommand, 
  DeleteCommand,
  UpdateCommand
} from '@aws-sdk/lib-dynamodb';

const client = new DynamoDBClient({
  region: process.env.AWS_REGION || 'eu-central-1'
});

const docClient = DynamoDBDocumentClient.from(client);

const USERS_TABLE = process.env.DYNAMODB_USERS_TABLE || 'zalt-users';

export interface VerificationCodeRecord {
  userId: string;
  realmId: string;
  email: string;
  codeHash: string;
  expiresAt: number;
  attempts: number;
  createdAt?: string;
}

/**
 * Save verification code to DynamoDB
 * Uses user record with verification_ prefix fields
 * Key: userId (matches DynamoDB table schema)
 */
export async function saveVerificationCode(data: VerificationCodeRecord): Promise<void> {
  const ttl = Math.floor(data.expiresAt / 1000); // DynamoDB TTL is in seconds
  
  await docClient.send(new UpdateCommand({
    TableName: USERS_TABLE,
    Key: {
      userId: data.userId  // Primary key matches DynamoDB schema
    },
    UpdateExpression: 'SET verification_code_hash = :hash, verification_expires_at = :expires, verification_attempts = :attempts, verification_email = :email, verification_ttl = :ttl',
    ExpressionAttributeValues: {
      ':hash': data.codeHash,
      ':expires': data.expiresAt,
      ':attempts': data.attempts,
      ':email': data.email,
      ':ttl': ttl
    }
  }));
}

/**
 * Get verification code data for a user
 */
export async function getVerificationCode(
  realmId: string, 
  userId: string
): Promise<VerificationCodeRecord | null> {
  const result = await docClient.send(new GetCommand({
    TableName: USERS_TABLE,
    Key: {
      userId: userId  // Primary key matches DynamoDB schema
    },
    ProjectionExpression: 'verification_code_hash, verification_expires_at, verification_attempts, verification_email'
  }));

  if (!result.Item || !result.Item.verification_code_hash) {
    return null;
  }

  return {
    userId,
    realmId,
    email: result.Item.verification_email,
    codeHash: result.Item.verification_code_hash,
    expiresAt: result.Item.verification_expires_at,
    attempts: result.Item.verification_attempts || 0
  };
}

/**
 * Increment verification attempts
 */
export async function incrementVerificationAttempts(
  realmId: string, 
  userId: string
): Promise<number> {
  const result = await docClient.send(new UpdateCommand({
    TableName: USERS_TABLE,
    Key: {
      userId: userId  // Primary key matches DynamoDB schema
    },
    UpdateExpression: 'SET verification_attempts = if_not_exists(verification_attempts, :zero) + :inc',
    ExpressionAttributeValues: {
      ':zero': 0,
      ':inc': 1
    },
    ReturnValues: 'UPDATED_NEW'
  }));

  return result.Attributes?.verification_attempts || 1;
}

/**
 * Clear verification code after successful verification
 */
export async function clearVerificationCode(
  realmId: string, 
  userId: string
): Promise<void> {
  await docClient.send(new UpdateCommand({
    TableName: USERS_TABLE,
    Key: {
      userId: userId  // Primary key matches DynamoDB schema
    },
    UpdateExpression: 'REMOVE verification_code_hash, verification_expires_at, verification_attempts, verification_email, verification_ttl'
  }));
}
