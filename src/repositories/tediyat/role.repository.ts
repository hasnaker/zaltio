/**
 * Tediyat Role Repository - DynamoDB operations for custom roles
 * System roles are defined in role.model.ts, this handles custom roles only
 * 
 * Validates: Requirements 17.1-17.4
 */

import {
  GetCommand,
  PutCommand,
  UpdateCommand,
  QueryCommand,
  DeleteCommand,
} from '@aws-sdk/lib-dynamodb';
import { dynamoDb } from '../../services/dynamodb.service';
import {
  Role,
  RoleDynamoDBItem,
  CreateRoleInput,
  UpdateRoleInput,
  generateRoleId,
} from '../../models/tediyat/role.model';

const TABLE_NAME = process.env.TEDIYAT_TABLE || 'zalt-tediyat';

/**
 * Convert DynamoDB item to Role
 */
function itemToRole(item: RoleDynamoDBItem): Role {
  return {
    id: item.id,
    tenant_id: item.tenant_id,
    name: item.name,
    description: item.description,
    permissions: item.permissions,
    inherits_from: item.inherits_from,
    is_system: item.is_system,
    created_at: item.created_at,
    updated_at: item.updated_at,
  };
}

/**
 * Create a custom role for a tenant
 */
export async function createRole(input: CreateRoleInput): Promise<Role> {
  const now = new Date().toISOString();
  const roleId = generateRoleId();

  const item: RoleDynamoDBItem = {
    PK: `ROLE#${roleId}`,
    SK: 'METADATA',
    GSI1PK: `TENANT#${input.tenant_id}#ROLES`,
    GSI1SK: `ROLE#${roleId}`,
    
    id: roleId,
    tenant_id: input.tenant_id,
    name: input.name,
    description: input.description,
    permissions: input.permissions,
    inherits_from: input.inherits_from,
    is_system: false,
    created_at: now,
    updated_at: now,
    entity_type: 'ROLE',
  };

  await dynamoDb.send(new PutCommand({
    TableName: TABLE_NAME,
    Item: item,
    ConditionExpression: 'attribute_not_exists(PK)',
  }));

  return itemToRole(item);
}

/**
 * Get role by ID
 */
export async function getRole(roleId: string): Promise<Role | null> {
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

  return itemToRole(result.Item as RoleDynamoDBItem);
}

/**
 * List custom roles for a tenant
 */
export async function listTenantRoles(
  tenantId: string,
  limit: number = 50,
  cursor?: string
): Promise<{ roles: Role[]; nextCursor?: string }> {
  const result = await dynamoDb.send(new QueryCommand({
    TableName: TABLE_NAME,
    IndexName: 'GSI1',
    KeyConditionExpression: 'GSI1PK = :tenantPk',
    ExpressionAttributeValues: {
      ':tenantPk': `TENANT#${tenantId}#ROLES`,
    },
    Limit: limit,
    ExclusiveStartKey: cursor ? JSON.parse(Buffer.from(cursor, 'base64').toString()) : undefined,
  }));

  const roles = (result.Items || []).map(item => 
    itemToRole(item as RoleDynamoDBItem)
  );

  return {
    roles,
    nextCursor: result.LastEvaluatedKey 
      ? Buffer.from(JSON.stringify(result.LastEvaluatedKey)).toString('base64')
      : undefined,
  };
}

/**
 * Find role by name within a tenant
 */
export async function findRoleByName(
  tenantId: string,
  name: string
): Promise<Role | null> {
  const { roles } = await listTenantRoles(tenantId, 100);
  return roles.find(r => r.name.toLowerCase() === name.toLowerCase()) || null;
}

/**
 * Update custom role
 */
export async function updateRole(
  roleId: string,
  input: UpdateRoleInput
): Promise<Role | null> {
  const existing = await getRole(roleId);
  if (!existing) {
    return null;
  }

  // Cannot update system roles
  if (existing.is_system) {
    throw new Error('Cannot modify system roles');
  }

  const now = new Date().toISOString();
  const updateExpressions: string[] = ['updated_at = :updatedAt'];
  const expressionAttributeNames: Record<string, string> = {};
  const expressionAttributeValues: Record<string, unknown> = {
    ':updatedAt': now,
  };

  if (input.name !== undefined) {
    updateExpressions.push('#name = :name');
    expressionAttributeNames['#name'] = 'name';
    expressionAttributeValues[':name'] = input.name;
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
    ExpressionAttributeNames: Object.keys(expressionAttributeNames).length > 0 
      ? expressionAttributeNames 
      : undefined,
    ExpressionAttributeValues: expressionAttributeValues,
    ReturnValues: 'ALL_NEW',
  }));

  if (!result.Attributes) {
    return null;
  }

  return itemToRole(result.Attributes as RoleDynamoDBItem);
}

/**
 * Delete custom role
 */
export async function deleteRole(roleId: string): Promise<boolean> {
  const existing = await getRole(roleId);
  if (!existing) {
    return false;
  }

  // Cannot delete system roles
  if (existing.is_system) {
    throw new Error('Cannot delete system roles');
  }

  try {
    await dynamoDb.send(new DeleteCommand({
      TableName: TABLE_NAME,
      Key: {
        PK: `ROLE#${roleId}`,
        SK: 'METADATA',
      },
    }));
    return true;
  } catch {
    return false;
  }
}
