/**
 * DynamoDB Service - Database operations for HSD Auth Platform
 * Validates: Requirements 7.1, 7.2 (AWS infrastructure)
 */

import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { AWS_CONFIG } from '../config/aws.config';

const client = new DynamoDBClient({ region: AWS_CONFIG.region });

export const dynamoDb = DynamoDBDocumentClient.from(client, {
  marshallOptions: {
    removeUndefinedValues: true,
    convertEmptyValues: false
  },
  unmarshallOptions: {
    wrapNumbers: false
  }
});

export const TableNames = {
  // Core tables (health check validates these)
  USERS: AWS_CONFIG.dynamodb.tables.users,
  REALMS: AWS_CONFIG.dynamodb.tables.realms,
  SESSIONS: AWS_CONFIG.dynamodb.tables.sessions,
  // Platform tables (SaaS customers)
  CUSTOMERS: AWS_CONFIG.dynamodb.platformTables.customers,
  API_KEYS: AWS_CONFIG.dynamodb.platformTables.apiKeys,
  USAGE: AWS_CONFIG.dynamodb.platformTables.usage,
  // Extended tables (optional, not validated by health check)
  TOKENS: AWS_CONFIG.dynamodb.extendedTables.tokens,
  DOCUMENTS: AWS_CONFIG.dynamodb.extendedTables.documents,
  AUDIT: AWS_CONFIG.dynamodb.extendedTables.audit,
  DEVICES: AWS_CONFIG.dynamodb.extendedTables.devices,
  MFA: AWS_CONFIG.dynamodb.extendedTables.mfa,
  WEBAUTHN: AWS_CONFIG.dynamodb.extendedTables.webauthn
} as const;
