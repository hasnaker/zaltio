/**
 * Tediyat Membership Repository - DynamoDB operations for memberships
 * Validates: Requirements 14.1, 15.1
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
  Membership,
  MembershipDynamoDBItem,
  CreateMembershipInput,
  UpdateMembershipInput,
  MembershipStatus,
} from '../../models/tediyat/membership.model';

const TABLE_NAME = process.env.TEDIYAT_TABLE || 'zalt-tediyat';

/**
 * Convert DynamoDB item to Membership
 */
function itemToMembership(item: MembershipDynamoDBItem): Membership {
  return {
    user_id: item.user_id,
    tenant_id: item.tenant_id,
    realm_id: item.realm_id,
    role_id: item.role_id,
    role_name: item.role_name,
    direct_permissions: item.direct_permissions,
    status: item.status,
    is_default: item.is_default,
    invited_by: item.invited_by,
    invited_at: item.invited_at,
    joined_at: item.joined_at,
    updated_at: item.updated_at,
  };
}

/**
 * Create a new membership
 */
export async function createMembership(input: CreateMembershipInput): Promise<Membership> {
  const now = new Date().toISOString();

  const item: MembershipDynamoDBItem = {
    PK: `USER#${input.user_id}#TENANT#${input.tenant_id}`,
    SK: 'MEMBERSHIP',
    GSI1PK: `TENANT#${input.tenant_id}#MEMBERS`,
    GSI1SK: `USER#${input.user_id}`,
    GSI2PK: `USER#${input.user_id}#MEMBERSHIPS`,
    GSI2SK: `TENANT#${input.tenant_id}`,
    GSI3PK: `TENANT#${input.tenant_id}#ROLE#${input.role_id}`,
    GSI3SK: `USER#${input.user_id}`,
    
    user_id: input.user_id,
    tenant_id: input.tenant_id,
    realm_id: input.realm_id,
    role_id: input.role_id,
    role_name: input.role_name,
    direct_permissions: input.direct_permissions,
    status: 'active',
    is_default: input.is_default || false,
    invited_by: input.invited_by,
    invited_at: input.invited_by ? now : undefined,
    joined_at: now,
    updated_at: now,
    entity_type: 'MEMBERSHIP',
  };

  await dynamoDb.send(new PutCommand({
    TableName: TABLE_NAME,
    Item: item,
    ConditionExpression: 'attribute_not_exists(PK)',
  }));

  return itemToMembership(item);
}

/**
 * Get membership by user and tenant
 */
export async function getMembership(
  userId: string,
  tenantId: string
): Promise<Membership | null> {
  const result = await dynamoDb.send(new GetCommand({
    TableName: TABLE_NAME,
    Key: {
      PK: `USER#${userId}#TENANT#${tenantId}`,
      SK: 'MEMBERSHIP',
    },
  }));

  if (!result.Item) {
    return null;
  }

  return itemToMembership(result.Item as MembershipDynamoDBItem);
}

/**
 * List all members of a tenant
 */
export async function listTenantMembers(
  tenantId: string,
  limit: number = 50,
  cursor?: string
): Promise<{ memberships: Membership[]; nextCursor?: string }> {
  const result = await dynamoDb.send(new QueryCommand({
    TableName: TABLE_NAME,
    IndexName: 'GSI1',
    KeyConditionExpression: 'GSI1PK = :tenantPk',
    FilterExpression: '#status = :active',
    ExpressionAttributeNames: {
      '#status': 'status',
    },
    ExpressionAttributeValues: {
      ':tenantPk': `TENANT#${tenantId}#MEMBERS`,
      ':active': 'active',
    },
    Limit: limit,
    ExclusiveStartKey: cursor ? JSON.parse(Buffer.from(cursor, 'base64').toString()) : undefined,
  }));

  const memberships = (result.Items || []).map(item => 
    itemToMembership(item as MembershipDynamoDBItem)
  );

  return {
    memberships,
    nextCursor: result.LastEvaluatedKey 
      ? Buffer.from(JSON.stringify(result.LastEvaluatedKey)).toString('base64')
      : undefined,
  };
}

/**
 * List all memberships for a user
 */
export async function listUserMemberships(
  userId: string,
  limit: number = 50,
  cursor?: string
): Promise<{ memberships: Membership[]; nextCursor?: string }> {
  const result = await dynamoDb.send(new QueryCommand({
    TableName: TABLE_NAME,
    IndexName: 'GSI2',
    KeyConditionExpression: 'GSI2PK = :userPk',
    FilterExpression: '#status = :active',
    ExpressionAttributeNames: {
      '#status': 'status',
    },
    ExpressionAttributeValues: {
      ':userPk': `USER#${userId}#MEMBERSHIPS`,
      ':active': 'active',
    },
    Limit: limit,
    ExclusiveStartKey: cursor ? JSON.parse(Buffer.from(cursor, 'base64').toString()) : undefined,
  }));

  const memberships = (result.Items || []).map(item => 
    itemToMembership(item as MembershipDynamoDBItem)
  );

  return {
    memberships,
    nextCursor: result.LastEvaluatedKey 
      ? Buffer.from(JSON.stringify(result.LastEvaluatedKey)).toString('base64')
      : undefined,
  };
}

/**
 * Count members with a specific role in a tenant
 */
export async function countMembersByRole(
  tenantId: string,
  roleId: string
): Promise<number> {
  const result = await dynamoDb.send(new QueryCommand({
    TableName: TABLE_NAME,
    IndexName: 'GSI3',
    KeyConditionExpression: 'GSI3PK = :rolePk',
    FilterExpression: '#status = :active',
    ExpressionAttributeNames: {
      '#status': 'status',
    },
    ExpressionAttributeValues: {
      ':rolePk': `TENANT#${tenantId}#ROLE#${roleId}`,
      ':active': 'active',
    },
    Select: 'COUNT',
  }));

  return result.Count || 0;
}

/**
 * Update membership
 */
export async function updateMembership(
  userId: string,
  tenantId: string,
  input: UpdateMembershipInput
): Promise<Membership | null> {
  const existing = await getMembership(userId, tenantId);
  if (!existing) {
    return null;
  }

  const now = new Date().toISOString();
  const updateExpressions: string[] = ['updated_at = :updatedAt'];
  const expressionAttributeNames: Record<string, string> = {};
  const expressionAttributeValues: Record<string, unknown> = {
    ':updatedAt': now,
  };

  if (input.role_id !== undefined) {
    updateExpressions.push('role_id = :roleId');
    expressionAttributeValues[':roleId'] = input.role_id;
    
    // Update GSI3 key
    updateExpressions.push('GSI3PK = :gsi3pk');
    expressionAttributeValues[':gsi3pk'] = `TENANT#${tenantId}#ROLE#${input.role_id}`;
  }

  if (input.role_name !== undefined) {
    updateExpressions.push('role_name = :roleName');
    expressionAttributeValues[':roleName'] = input.role_name;
  }

  if (input.direct_permissions !== undefined) {
    updateExpressions.push('direct_permissions = :directPerms');
    expressionAttributeValues[':directPerms'] = input.direct_permissions;
  }

  if (input.status !== undefined) {
    updateExpressions.push('#status = :status');
    expressionAttributeNames['#status'] = 'status';
    expressionAttributeValues[':status'] = input.status;
  }

  if (input.is_default !== undefined) {
    updateExpressions.push('is_default = :isDefault');
    expressionAttributeValues[':isDefault'] = input.is_default;
  }

  const result = await dynamoDb.send(new UpdateCommand({
    TableName: TABLE_NAME,
    Key: {
      PK: `USER#${userId}#TENANT#${tenantId}`,
      SK: 'MEMBERSHIP',
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

  return itemToMembership(result.Attributes as MembershipDynamoDBItem);
}

/**
 * Delete membership (soft delete by setting status to suspended)
 */
export async function deleteMembership(
  userId: string,
  tenantId: string
): Promise<boolean> {
  const result = await updateMembership(userId, tenantId, { status: 'suspended' });
  return result !== null;
}

/**
 * Hard delete membership (for testing only)
 */
export async function hardDeleteMembership(
  userId: string,
  tenantId: string
): Promise<boolean> {
  try {
    await dynamoDb.send(new DeleteCommand({
      TableName: TABLE_NAME,
      Key: {
        PK: `USER#${userId}#TENANT#${tenantId}`,
        SK: 'MEMBERSHIP',
      },
    }));
    return true;
  } catch {
    return false;
  }
}

/**
 * Check if user has membership in tenant
 */
export async function hasMembership(
  userId: string,
  tenantId: string
): Promise<boolean> {
  const membership = await getMembership(userId, tenantId);
  return membership !== null && membership.status === 'active';
}

/**
 * Set default tenant for user (unset others)
 */
export async function setDefaultTenant(
  userId: string,
  tenantId: string
): Promise<void> {
  // Get all user memberships
  const { memberships } = await listUserMemberships(userId, 100);
  
  // Update all to non-default, then set the target as default
  for (const membership of memberships) {
    if (membership.tenant_id === tenantId) {
      await updateMembership(userId, tenantId, { is_default: true });
    } else if (membership.is_default) {
      await updateMembership(userId, membership.tenant_id, { is_default: false });
    }
  }
}
