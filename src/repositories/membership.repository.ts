/**
 * Membership Repository - DynamoDB operations for user-organization memberships
 * Validates: Requirements 2.1, 2.2, 2.3, 2.4, 2.5, 2.6
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
  Membership,
  MembershipRecord,
  CreateMembershipInput,
  UpdateMembershipInput,
  MembershipListOptions,
  UserMembershipsOptions,
  MembershipListResult,
  MembershipWithUser,
  recordToMembership,
} from '../models/membership.model';
import { incrementMemberCount, getOrganization } from './organization.repository';

const TABLE_NAME = process.env.MEMBERSHIPS_TABLE || 'zalt-memberships';

/**
 * Create a new membership
 */
export async function createMembership(
  input: CreateMembershipInput
): Promise<Membership> {
  // Check if membership already exists
  const existing = await getMembership(input.user_id, input.org_id);
  if (existing) {
    throw new Error('User is already a member of this organization');
  }

  // Check organization user limit
  const org = await getOrganization(input.org_id);
  if (org && org.settings.user_limit) {
    if (org.member_count >= org.settings.user_limit) {
      throw new Error('Organization has reached its user limit');
    }
  }

  const now = Date.now();
  const record: MembershipRecord = {
    PK: `MEMBERSHIP#${input.user_id}`,
    SK: `ORG#${input.org_id}`,
    user_id: input.user_id,
    org_id: input.org_id,
    realm_id: input.realm_id,
    role_ids: input.role_ids || [],
    direct_permissions: input.direct_permissions || [],
    is_default: input.is_default || false,
    status: input.invited_by ? 'invited' : 'active',
    invited_by: input.invited_by,
    invited_at: input.invited_by ? now : undefined,
    joined_at: input.invited_by ? undefined : now,
    created_at: now,
    updated_at: now,
    GSI1PK: `ORG#${input.org_id}`,
    GSI1SK: `USER#${input.user_id}`,
    GSI2PK: `REALM#${input.realm_id}`,
    GSI2SK: `USER#${input.user_id}#ORG#${input.org_id}`,
  };

  await dynamoDb.send(new PutCommand({
    TableName: TABLE_NAME,
    Item: record,
    ConditionExpression: 'attribute_not_exists(PK) AND attribute_not_exists(SK)',
  }));

  // Increment organization member count
  await incrementMemberCount(input.org_id, 1);

  return recordToMembership(record);
}

/**
 * Get membership by user and organization
 */
export async function getMembership(
  userId: string,
  orgId: string
): Promise<Membership | null> {
  const result = await dynamoDb.send(new GetCommand({
    TableName: TABLE_NAME,
    Key: {
      PK: `MEMBERSHIP#${userId}`,
      SK: `ORG#${orgId}`,
    },
  }));

  if (!result.Item) {
    return null;
  }

  return recordToMembership(result.Item as MembershipRecord);
}

/**
 * List members of an organization
 */
export async function listOrganizationMembers(
  options: MembershipListOptions
): Promise<MembershipListResult> {
  const { org_id, status, limit = 50, cursor } = options;

  let filterExpression: string | undefined;
  const expressionAttributeValues: Record<string, unknown> = {
    ':orgId': `ORG#${org_id}`,
  };

  if (status) {
    filterExpression = '#status = :status';
    expressionAttributeValues[':status'] = status;
  }

  const result = await dynamoDb.send(new QueryCommand({
    TableName: TABLE_NAME,
    IndexName: 'GSI1',
    KeyConditionExpression: 'GSI1PK = :orgId',
    FilterExpression: filterExpression,
    ExpressionAttributeValues: expressionAttributeValues,
    ExpressionAttributeNames: status ? { '#status': 'status' } : undefined,
    Limit: limit,
    ExclusiveStartKey: cursor ? JSON.parse(Buffer.from(cursor, 'base64').toString()) : undefined,
  }));

  const memberships: MembershipWithUser[] = (result.Items || []).map(item => ({
    ...recordToMembership(item as MembershipRecord),
    // User details would be populated by service layer
  }));

  return {
    memberships,
    next_cursor: result.LastEvaluatedKey
      ? Buffer.from(JSON.stringify(result.LastEvaluatedKey)).toString('base64')
      : undefined,
  };
}

/**
 * Get all memberships for a user
 */
export async function getUserMemberships(
  options: UserMembershipsOptions
): Promise<Membership[]> {
  const { user_id, realm_id, status } = options;

  let filterExpression: string | undefined;
  const expressionAttributeValues: Record<string, unknown> = {
    ':userId': `MEMBERSHIP#${user_id}`,
  };
  const expressionAttributeNames: Record<string, string> = {};

  const filters: string[] = [];
  
  if (realm_id) {
    filters.push('realm_id = :realmId');
    expressionAttributeValues[':realmId'] = realm_id;
  }

  if (status) {
    filters.push('#status = :status');
    expressionAttributeValues[':status'] = status;
    expressionAttributeNames['#status'] = 'status';
  }

  if (filters.length > 0) {
    filterExpression = filters.join(' AND ');
  }

  const result = await dynamoDb.send(new QueryCommand({
    TableName: TABLE_NAME,
    KeyConditionExpression: 'PK = :userId',
    FilterExpression: filterExpression,
    ExpressionAttributeValues: expressionAttributeValues,
    ExpressionAttributeNames: Object.keys(expressionAttributeNames).length > 0 
      ? expressionAttributeNames 
      : undefined,
  }));

  return (result.Items || []).map(item => recordToMembership(item as MembershipRecord));
}

/**
 * Get user's default organization membership
 */
export async function getUserDefaultMembership(
  userId: string,
  realmId?: string
): Promise<Membership | null> {
  const memberships = await getUserMemberships({
    user_id: userId,
    realm_id: realmId,
    status: 'active',
  });

  // Find default membership
  const defaultMembership = memberships.find(m => m.is_default);
  if (defaultMembership) {
    return defaultMembership;
  }

  // Return first active membership if no default
  return memberships.length > 0 ? memberships[0] : null;
}

/**
 * Update membership
 */
export async function updateMembership(
  userId: string,
  orgId: string,
  input: UpdateMembershipInput
): Promise<Membership | null> {
  const existing = await getMembership(userId, orgId);
  if (!existing) {
    return null;
  }

  const now = Date.now();
  const updateExpressions: string[] = ['updated_at = :updatedAt'];
  const expressionAttributeValues: Record<string, unknown> = {
    ':updatedAt': now,
  };
  const expressionAttributeNames: Record<string, string> = {};

  if (input.role_ids !== undefined) {
    updateExpressions.push('role_ids = :roleIds');
    expressionAttributeValues[':roleIds'] = input.role_ids;
  }

  if (input.direct_permissions !== undefined) {
    updateExpressions.push('direct_permissions = :directPermissions');
    expressionAttributeValues[':directPermissions'] = input.direct_permissions;
  }

  if (input.is_default !== undefined) {
    updateExpressions.push('is_default = :isDefault');
    expressionAttributeValues[':isDefault'] = input.is_default;

    // If setting as default, unset other defaults for this user
    if (input.is_default) {
      await unsetOtherDefaults(userId, orgId);
    }
  }

  if (input.status !== undefined) {
    updateExpressions.push('#status = :status');
    expressionAttributeNames['#status'] = 'status';
    expressionAttributeValues[':status'] = input.status;

    // Set joined_at when status changes to active
    if (input.status === 'active' && existing.status === 'invited') {
      updateExpressions.push('joined_at = :joinedAt');
      expressionAttributeValues[':joinedAt'] = now;
    }
  }

  const result = await dynamoDb.send(new UpdateCommand({
    TableName: TABLE_NAME,
    Key: {
      PK: `MEMBERSHIP#${userId}`,
      SK: `ORG#${orgId}`,
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

  return recordToMembership(result.Attributes as MembershipRecord);
}

/**
 * Unset default flag on other memberships for a user
 */
async function unsetOtherDefaults(userId: string, exceptOrgId: string): Promise<void> {
  const memberships = await getUserMemberships({ user_id: userId });
  
  for (const membership of memberships) {
    if (membership.org_id !== exceptOrgId && membership.is_default) {
      await dynamoDb.send(new UpdateCommand({
        TableName: TABLE_NAME,
        Key: {
          PK: `MEMBERSHIP#${userId}`,
          SK: `ORG#${membership.org_id}`,
        },
        UpdateExpression: 'SET is_default = :false, updated_at = :now',
        ExpressionAttributeValues: {
          ':false': false,
          ':now': Date.now(),
        },
      }));
    }
  }
}

/**
 * Delete membership
 */
export async function deleteMembership(
  userId: string,
  orgId: string
): Promise<boolean> {
  const existing = await getMembership(userId, orgId);
  if (!existing) {
    return false;
  }

  await dynamoDb.send(new DeleteCommand({
    TableName: TABLE_NAME,
    Key: {
      PK: `MEMBERSHIP#${userId}`,
      SK: `ORG#${orgId}`,
    },
  }));

  // Decrement organization member count
  await incrementMemberCount(orgId, -1);

  return true;
}

/**
 * Check if user is member of organization
 */
export async function isMember(userId: string, orgId: string): Promise<boolean> {
  const membership = await getMembership(userId, orgId);
  return membership !== null && membership.status === 'active';
}

/**
 * Check if user has specific role in organization
 */
export async function hasRole(
  userId: string,
  orgId: string,
  roleId: string
): Promise<boolean> {
  const membership = await getMembership(userId, orgId);
  if (!membership || membership.status !== 'active') {
    return false;
  }
  return membership.role_ids.includes(roleId);
}
