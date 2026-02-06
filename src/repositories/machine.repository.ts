/**
 * Machine Repository - DynamoDB operations for M2M machines
 * Table: zalt-machines
 * PK: REALM#{realm_id}#MACHINE#{machine_id}
 * SK: MACHINE
 * GSI: client-id-index (client_id → machine)
 * GSI: realm-index (realm_id → machines)
 * 
 * Validates: Requirements 1.1, 1.2 (M2M Authentication)
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
  Machine,
  CreateMachineInput,
  MachineResponse,
  MachineWithSecret,
  MachineStatus,
  CLIENT_ID_PREFIX
} from '../models/machine.model';
import { hashPassword, verifyPassword } from '../utils/password';
import { randomBytes, createHash } from 'crypto';

const TABLE_NAME = 'zalt-machines';
const CLIENT_ID_INDEX = 'client-id-index';
const REALM_INDEX = 'realm-index';

/**
 * Generate unique machine ID
 */
function generateMachineId(): string {
  return `machine_${randomBytes(12).toString('hex')}`;
}

/**
 * Generate client ID (public identifier)
 */
function generateClientId(): string {
  return `${CLIENT_ID_PREFIX}${randomBytes(12).toString('hex')}`;
}

/**
 * Generate client secret (high entropy)
 */
function generateClientSecret(): string {
  // 48 bytes = 64 base64 chars, very high entropy
  return randomBytes(48).toString('base64url');
}

/**
 * Create composite primary key
 */
function createPK(realmId: string, machineId: string): string {
  return `REALM#${realmId}#MACHINE#${machineId}`;
}

/**
 * Create a new machine
 * Returns the client secret only once - it cannot be retrieved later
 */
export async function createMachine(input: CreateMachineInput): Promise<MachineWithSecret> {
  const machineId = generateMachineId();
  const clientId = generateClientId();
  const clientSecret = generateClientSecret();
  const now = new Date().toISOString();
  
  // Hash the client secret with Argon2id (same as passwords)
  const clientSecretHash = await hashPassword(clientSecret);
  
  const machine: Machine = {
    id: machineId,
    realm_id: input.realm_id,
    name: input.name,
    description: input.description,
    client_id: clientId,
    client_secret_hash: clientSecretHash,
    scopes: input.scopes,
    allowed_targets: input.allowed_targets || [],
    status: 'active',
    created_at: now,
    updated_at: now,
    created_by: input.created_by,
    rate_limit: input.rate_limit || 1000,
    allowed_ips: input.allowed_ips
  };
  
  await dynamoDb.send(new PutCommand({
    TableName: TABLE_NAME,
    Item: {
      pk: createPK(input.realm_id, machineId),
      sk: 'MACHINE',
      ...machine
    },
    ConditionExpression: 'attribute_not_exists(pk)'
  }));
  
  // Return machine response with secret (only time it's available)
  return {
    machine: toMachineResponse(machine),
    client_secret: clientSecret
  };
}

/**
 * Get machine by ID
 */
export async function getMachineById(realmId: string, machineId: string): Promise<Machine | null> {
  const result = await dynamoDb.send(new GetCommand({
    TableName: TABLE_NAME,
    Key: {
      pk: createPK(realmId, machineId),
      sk: 'MACHINE'
    }
  }));
  
  if (!result.Item) {
    return null;
  }
  
  return itemToMachine(result.Item);
}

/**
 * Get machine by client ID (for authentication)
 */
export async function getMachineByClientId(clientId: string): Promise<Machine | null> {
  const result = await dynamoDb.send(new QueryCommand({
    TableName: TABLE_NAME,
    IndexName: CLIENT_ID_INDEX,
    KeyConditionExpression: 'client_id = :clientId',
    ExpressionAttributeValues: {
      ':clientId': clientId
    },
    Limit: 1
  }));
  
  if (!result.Items || result.Items.length === 0) {
    return null;
  }
  
  return itemToMachine(result.Items[0]);
}

/**
 * Authenticate machine with client credentials
 */
export async function authenticateMachine(
  clientId: string,
  clientSecret: string
): Promise<Machine | null> {
  const machine = await getMachineByClientId(clientId);
  
  if (!machine) {
    return null;
  }
  
  // Check if machine is active
  if (machine.status !== 'active') {
    return null;
  }
  
  // Verify client secret
  const isValid = await verifyPassword(clientSecret, machine.client_secret_hash);
  if (!isValid) {
    return null;
  }
  
  // Update last used timestamp (fire and forget)
  updateLastUsed(machine.realm_id, machine.id).catch(() => {});
  
  return machine;
}

/**
 * List all machines in a realm
 */
export async function listMachinesByRealm(realmId: string): Promise<MachineResponse[]> {
  const result = await dynamoDb.send(new QueryCommand({
    TableName: TABLE_NAME,
    IndexName: REALM_INDEX,
    KeyConditionExpression: 'realm_id = :realmId',
    FilterExpression: '#status <> :deleted',
    ExpressionAttributeNames: {
      '#status': 'status'
    },
    ExpressionAttributeValues: {
      ':realmId': realmId,
      ':deleted': 'deleted'
    }
  }));
  
  if (!result.Items) {
    return [];
  }
  
  return result.Items.map(item => toMachineResponse(itemToMachine(item)));
}

/**
 * Update machine configuration
 */
export async function updateMachine(
  realmId: string,
  machineId: string,
  updates: Partial<Pick<Machine, 'name' | 'description' | 'scopes' | 'allowed_targets' | 'rate_limit' | 'allowed_ips' | 'status'>>
): Promise<Machine | null> {
  const now = new Date().toISOString();
  
  // Build update expression dynamically
  const updateParts: string[] = ['updated_at = :now'];
  const expressionValues: Record<string, unknown> = { ':now': now };
  const expressionNames: Record<string, string> = {};
  
  if (updates.name !== undefined) {
    updateParts.push('#name = :name');
    expressionValues[':name'] = updates.name;
    expressionNames['#name'] = 'name';
  }
  
  if (updates.description !== undefined) {
    updateParts.push('description = :description');
    expressionValues[':description'] = updates.description;
  }
  
  if (updates.scopes !== undefined) {
    updateParts.push('scopes = :scopes');
    expressionValues[':scopes'] = updates.scopes;
  }
  
  if (updates.allowed_targets !== undefined) {
    updateParts.push('allowed_targets = :targets');
    expressionValues[':targets'] = updates.allowed_targets;
  }
  
  if (updates.rate_limit !== undefined) {
    updateParts.push('rate_limit = :rateLimit');
    expressionValues[':rateLimit'] = updates.rate_limit;
  }
  
  if (updates.allowed_ips !== undefined) {
    updateParts.push('allowed_ips = :allowedIps');
    expressionValues[':allowedIps'] = updates.allowed_ips;
  }
  
  if (updates.status !== undefined) {
    updateParts.push('#status = :status');
    expressionValues[':status'] = updates.status;
    expressionNames['#status'] = 'status';
  }
  
  const result = await dynamoDb.send(new UpdateCommand({
    TableName: TABLE_NAME,
    Key: {
      pk: createPK(realmId, machineId),
      sk: 'MACHINE'
    },
    UpdateExpression: `SET ${updateParts.join(', ')}`,
    ExpressionAttributeValues: expressionValues,
    ExpressionAttributeNames: Object.keys(expressionNames).length > 0 ? expressionNames : undefined,
    ReturnValues: 'ALL_NEW',
    ConditionExpression: 'attribute_exists(pk)'
  }));
  
  if (!result.Attributes) {
    return null;
  }
  
  return itemToMachine(result.Attributes);
}

/**
 * Rotate machine credentials (generate new client secret)
 */
export async function rotateCredentials(
  realmId: string,
  machineId: string
): Promise<{ clientId: string; clientSecret: string } | null> {
  const machine = await getMachineById(realmId, machineId);
  
  if (!machine || machine.status !== 'active') {
    return null;
  }
  
  const newClientSecret = generateClientSecret();
  const newSecretHash = await hashPassword(newClientSecret);
  const now = new Date().toISOString();
  
  await dynamoDb.send(new UpdateCommand({
    TableName: TABLE_NAME,
    Key: {
      pk: createPK(realmId, machineId),
      sk: 'MACHINE'
    },
    UpdateExpression: 'SET client_secret_hash = :hash, updated_at = :now',
    ExpressionAttributeValues: {
      ':hash': newSecretHash,
      ':now': now
    },
    ConditionExpression: 'attribute_exists(pk)'
  }));
  
  return {
    clientId: machine.client_id,
    clientSecret: newClientSecret
  };
}

/**
 * Soft delete machine (set status to deleted)
 */
export async function deleteMachine(realmId: string, machineId: string): Promise<boolean> {
  try {
    const now = new Date().toISOString();
    
    await dynamoDb.send(new UpdateCommand({
      TableName: TABLE_NAME,
      Key: {
        pk: createPK(realmId, machineId),
        sk: 'MACHINE'
      },
      UpdateExpression: 'SET #status = :status, updated_at = :now, deleted_at = :now',
      ExpressionAttributeNames: {
        '#status': 'status'
      },
      ExpressionAttributeValues: {
        ':status': 'deleted' as MachineStatus,
        ':now': now
      },
      ConditionExpression: 'attribute_exists(pk)'
    }));
    
    return true;
  } catch {
    return false;
  }
}

/**
 * Hard delete machine (permanent removal)
 */
export async function hardDeleteMachine(realmId: string, machineId: string): Promise<boolean> {
  try {
    await dynamoDb.send(new DeleteCommand({
      TableName: TABLE_NAME,
      Key: {
        pk: createPK(realmId, machineId),
        sk: 'MACHINE'
      }
    }));
    return true;
  } catch {
    return false;
  }
}

/**
 * Update last used timestamp
 */
async function updateLastUsed(realmId: string, machineId: string): Promise<void> {
  const now = new Date().toISOString();
  
  await dynamoDb.send(new UpdateCommand({
    TableName: TABLE_NAME,
    Key: {
      pk: createPK(realmId, machineId),
      sk: 'MACHINE'
    },
    UpdateExpression: 'SET last_used_at = :now',
    ExpressionAttributeValues: {
      ':now': now
    }
  }));
}

/**
 * Count machines in a realm
 */
export async function countMachinesByRealm(realmId: string): Promise<number> {
  const result = await dynamoDb.send(new QueryCommand({
    TableName: TABLE_NAME,
    IndexName: REALM_INDEX,
    KeyConditionExpression: 'realm_id = :realmId',
    FilterExpression: '#status <> :deleted',
    ExpressionAttributeNames: {
      '#status': 'status'
    },
    ExpressionAttributeValues: {
      ':realmId': realmId,
      ':deleted': 'deleted'
    },
    Select: 'COUNT'
  }));
  
  return result.Count || 0;
}

/**
 * Check if machine has specific scope
 */
export function machineHasScope(machine: Machine, requiredScope: string): boolean {
  // admin:all grants all scopes
  if (machine.scopes.includes('admin:all')) {
    return true;
  }
  return machine.scopes.includes(requiredScope);
}

/**
 * Check if machine can call target machine
 */
export function machineCanCallTarget(machine: Machine, targetMachineId: string): boolean {
  // Empty allowed_targets means can call any machine
  if (machine.allowed_targets.length === 0) {
    return true;
  }
  return machine.allowed_targets.includes(targetMachineId);
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Convert DynamoDB item to Machine
 */
function itemToMachine(item: Record<string, unknown>): Machine {
  return {
    id: item.id as string,
    realm_id: item.realm_id as string,
    name: item.name as string,
    description: item.description as string | undefined,
    client_id: item.client_id as string,
    client_secret_hash: item.client_secret_hash as string,
    scopes: item.scopes as string[],
    allowed_targets: item.allowed_targets as string[] || [],
    status: item.status as MachineStatus,
    created_at: item.created_at as string,
    updated_at: item.updated_at as string,
    last_used_at: item.last_used_at as string | undefined,
    created_by: item.created_by as string | undefined,
    rate_limit: item.rate_limit as number | undefined,
    allowed_ips: item.allowed_ips as string[] | undefined
  };
}

/**
 * Convert Machine to MachineResponse (exclude sensitive data)
 */
function toMachineResponse(machine: Machine): MachineResponse {
  return {
    id: machine.id,
    realm_id: machine.realm_id,
    name: machine.name,
    description: machine.description,
    client_id: machine.client_id,
    scopes: machine.scopes,
    allowed_targets: machine.allowed_targets,
    status: machine.status,
    created_at: machine.created_at,
    updated_at: machine.updated_at,
    last_used_at: machine.last_used_at,
    rate_limit: machine.rate_limit,
    allowed_ips: machine.allowed_ips
  };
}
