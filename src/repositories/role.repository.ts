/**
 * Role Repository - DynamoDB operations for roles
 * Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.6
 */

import {
  GetCommand,
  PutCommand,
  UpdateCommand,
  DeleteCommand,
  QueryCommand,
} from '@aws-sdk/lib-dynamodb';
import { dynamoDb } from '../services/dynamodb.service';
import {
  Role,
  RoleRecord,
  CreateRoleInput,
  UpdateRoleInput,
  RoleListOptions,
  RoleListResult,
  recordToRole,
  isSystemRole,
  SYSTEM_ROLES,
} from '../models/role.model';
import * as crypto from 'crypto';

const TABLE_NAME = process.env.ROLES_TABLE || 'zalt-roles';

/**
 * Generate unique role ID
 */
function generateRoleId(): string {
  return `role_${crypto.randomUUID().replace(/-/g, '').substring(0, 24)}`;
}

/**
 * Create a new role
 */
export async function createRole(input: CreateRoleInput): Promise<Role> {
  // Check name uniqueness within scope (realm or org)
  const existingByName = await findRoleByName(
    input.realm_id,
    input.name,
    input.org_id
  );
  if (existingByName) {
    throw new Error(`Role with name "${input.name}" already exists`);
  }

  const now = Date.now();
  const roleId = generateRoleId();

  const record: RoleRecord = {
    PK: `ROLE#${roleId}`,
    SK: 'METADATA',
    role_id: roleId,
    realm_id: input.realm_id,
    org_id: input.org_id,
    name: input.name,
    description: input.description,
    permissions: input.permissions || [],
    is_system: false,
    inherits_from: input.inherits_from,
    created_at: now,
    updated_at: now,
    GSI1PK: input.org_id ? `ORG#${input.org_id}` : `REALM#${input.realm_id}`,
    GSI1SK: `ROLE#${input.name}`,
  };

  await dynamoDb.send(new PutCommand({
    TableName: TABLE_NAME,
    Item: record,
    ConditionExpression: 'attribute_not_exists(PK)',
  }));

  return recordToRole(record);
}

/**
 * Get role by ID
 */
export async function getRole(roleId: string): Promise<Role | null> {
  // Check if it's a system role first
  if (isSystemRole(roleId)) {
    const systemRole = Object.values(SYSTEM_ROLES).find(r => r.id === roleId);
    if (systemRole) {
      return {
        id: systemRole.id,
        realm_id: '*', // System roles apply to all realms
        name: systemRole.name,
        description: systemRole.description,
        permissions: [...systemRole.permissions],
        is_system: true,
        created_at: new Date(0).toISOString(),
        updated_at: new Date(0).toISOString(),
      };
    }
  }

  const result = await dynamoDb.send(new GetCommand({
    TableName: TABLE_NAME,
    Key: {
      PK: `ROLE#${roleId}`,
      SK: 'METADATA',
    },
  }));

  if (!result.Item) {
    return null;
  }

  return recordToRole(result.Item as RoleRecord);
}

/**
 * Find role by name within scope
 */
export async function findRoleByName(
  realmId: string,
  name: string,
  orgId?: string
): Promise<Role | null> {
  // Check system roles first
  const systemRole = Object.values(SYSTEM_ROLES).find(
    r => r.name.toLowerCase() === name.toLowerCase()
  );
  if (systemRole) {
    return {
      id: systemRole.id,
      realm_id: realmId,
      name: systemRole.name,
      description: systemRole.description,
      permissions: [...systemRole.permissions],
      is_system: true,
      created_at: new Date(0).toISOString(),
      updated_at: new Date(0).toISOString(),
    };
  }

  const gsi1pk = orgId ? `ORG#${orgId}` : `REALM#${realmId}`;

  const result = await dynamoDb.send(new QueryCommand({
    TableName: TABLE_NAME,
    IndexName: 'GSI1',
    KeyConditionExpression: 'GSI1PK = :gsi1pk AND GSI1SK = :gsi1sk',
    ExpressionAttributeValues: {
      ':gsi1pk': gsi1pk,
      ':gsi1sk': `ROLE#${name}`,
    },
    Limit: 1,
  }));

  if (!result.Items || result.Items.length === 0) {
    return null;
  }

  return recordToRole(result.Items[0] as RoleRecord);
}

/**
 * List roles in a realm or organization
 */
export async function listRoles(options: RoleListOptions): Promise<RoleListResult> {
  const { realm_id, org_id, include_system = true, limit = 50, cursor } = options;

  const roles: Role[] = [];

  // Add system roles if requested
  if (include_system) {
    for (const systemRole of Object.values(SYSTEM_ROLES)) {
      roles.push({
        id: systemRole.id,
        realm_id: realm_id,
        name: systemRole.name,
        description: systemRole.description,
        permissions: [...systemRole.permissions],
        is_system: true,
        created_at: new Date(0).toISOString(),
        updated_at: new Date(0).toISOString(),
      });
    }
  }

  // Query custom roles
  const gsi1pk = org_id ? `ORG#${org_id}` : `REALM#${realm_id}`;

  const result = await dynamoDb.send(new QueryCommand({
    TableName: TABLE_NAME,
    IndexName: 'GSI1',
    KeyConditionExpression: 'GSI1PK = :gsi1pk',
    ExpressionAttributeValues: {
      ':gsi1pk': gsi1pk,
    },
    Limit: limit,
    ExclusiveStartKey: cursor 
      ? JSON.parse(Buffer.from(cursor, 'base64').toString()) 
      : undefined,
  }));

  const customRoles = (result.Items || []).map(item => 
    recordToRole(item as RoleRecord)
  );

  roles.push(...customRoles);

  return {
    roles,
    next_cursor: result.LastEvaluatedKey
      ? Buffer.from(JSON.stringify(result.LastEvaluatedKey)).toString('base64')
      : undefined,
  };
}


/**
 * Update role
 */
export async function updateRole(
  roleId: string,
  input: UpdateRoleInput
): Promise<Role | null> {
  // Prevent modification of system roles
  if (isSystemRole(roleId)) {
    throw new Error('System roles cannot be modified');
  }

  const existing = await getRole(roleId);
  if (!existing) {
    return null;
  }

  const now = Date.now();
  const updateExpressions: string[] = ['updated_at = :updatedAt'];
  const expressionAttributeValues: Record<string, unknown> = {
    ':updatedAt': now,
  };
  const expressionAttributeNames: Record<string, string> = {};

  if (input.name !== undefined) {
    // Check name uniqueness
    const existingByName = await findRoleByName(
      existing.realm_id,
      input.name,
      existing.org_id
    );
    if (existingByName && existingByName.id !== roleId) {
      throw new Error(`Role with name "${input.name}" already exists`);
    }
    updateExpressions.push('#name = :name');
    expressionAttributeNames['#name'] = 'name';
    expressionAttributeValues[':name'] = input.name;
    
    // Update GSI1SK for name-based lookups
    updateExpressions.push('GSI1SK = :gsi1sk');
    expressionAttributeValues[':gsi1sk'] = `ROLE#${input.name}`;
  }

  if (input.description !== undefined) {
    updateExpressions.push('description = :description');
    expressionAttributeValues[':description'] = input.description;
  }

  if (input.permissions !== undefined) {
    updateExpressions.push('permissions = :permissions');
    expressionAttributeValues[':permissions'] = input.permissions;
  }

  if (input.inherits_from !== undefined) {
    updateExpressions.push('inherits_from = :inheritsFrom');
    expressionAttributeValues[':inheritsFrom'] = input.inherits_from;
  }

  const result = await dynamoDb.send(new UpdateCommand({
    TableName: TABLE_NAME,
    Key: {
      PK: `ROLE#${roleId}`,
      SK: 'METADATA',
    },
    UpdateExpression: `SET ${updateExpressions.join(', ')}`,
    ExpressionAttributeValues: expressionAttributeValues,
    ExpressionAttributeNames: Object.keys(expressionAttributeNames).length > 0
      ? expressionAttributeNames
      : undefined,
    ReturnValues: 'ALL_NEW',
  }));

  if (!result.Attributes) {
    return null;
  }

  return recordToRole(result.Attributes as RoleRecord);
}

/**
 * Delete role
 */
export async function deleteRole(roleId: string): Promise<boolean> {
  // Prevent deletion of system roles
  if (isSystemRole(roleId)) {
    throw new Error('System roles cannot be deleted');
  }

  const existing = await getRole(roleId);
  if (!existing) {
    return false;
  }

  // TODO: Check if role is in use by any memberships
  // This would require a query across memberships table

  await dynamoDb.send(new DeleteCommand({
    TableName: TABLE_NAME,
    Key: {
      PK: `ROLE#${roleId}`,
      SK: 'METADATA',
    },
  }));

  return true;
}

/**
 * Get effective permissions for a role (including inherited)
 */
export async function getEffectivePermissions(roleId: string): Promise<string[]> {
  const role = await getRole(roleId);
  if (!role) {
    return [];
  }

  const permissions = new Set<string>(role.permissions);

  // Process inherited roles
  if (role.inherits_from && role.inherits_from.length > 0) {
    for (const inheritedRoleId of role.inherits_from) {
      const inheritedPermissions = await getEffectivePermissions(inheritedRoleId);
      inheritedPermissions.forEach(p => permissions.add(p));
    }
  }

  return Array.from(permissions);
}

/**
 * Get permissions for multiple roles
 */
export async function getPermissionsForRoles(roleIds: string[]): Promise<string[]> {
  const allPermissions = new Set<string>();

  for (const roleId of roleIds) {
    const permissions = await getEffectivePermissions(roleId);
    permissions.forEach(p => allPermissions.add(p));
  }

  return Array.from(allPermissions);
}

/**
 * Check if role exists
 */
export async function roleExists(roleId: string): Promise<boolean> {
  if (isSystemRole(roleId)) {
    return true;
  }
  const role = await getRole(roleId);
  return role !== null;
}

/**
 * Validate role IDs exist
 */
export async function validateRoleIds(roleIds: string[]): Promise<{
  valid: string[];
  invalid: string[];
}> {
  const valid: string[] = [];
  const invalid: string[] = [];

  for (const roleId of roleIds) {
    if (await roleExists(roleId)) {
      valid.push(roleId);
    } else {
      invalid.push(roleId);
    }
  }

  return { valid, invalid };
}
