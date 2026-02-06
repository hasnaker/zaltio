/**
 * Organization Repository - DynamoDB operations for organizations
 * Validates: Requirements 1.1, 1.2, 1.3, 1.4, 1.5, 1.6
 */

import {
  GetCommand,
  PutCommand,
  UpdateCommand,
  QueryCommand,
  DeleteCommand,
} from '@aws-sdk/lib-dynamodb';
import { dynamoDb } from '../services/dynamodb.service';
import {
  Organization,
  OrganizationRecord,
  CreateOrganizationInput,
  UpdateOrganizationInput,
  OrganizationListOptions,
  OrganizationListResult,
  recordToOrganization,
  generateSlug,
} from '../models/organization.model';
import * as crypto from 'crypto';

const TABLE_NAME = process.env.ORGANIZATIONS_TABLE || 'zalt-organizations';

/**
 * Generate unique organization ID
 */
function generateOrgId(): string {
  return `org_${crypto.randomUUID().replace(/-/g, '').substring(0, 24)}`;
}

/**
 * Create a new organization
 */
export async function createOrganization(
  input: CreateOrganizationInput
): Promise<Organization> {
  const now = Date.now();
  const orgId = generateOrgId();
  const slug = input.slug || generateSlug(input.name);

  // Check slug uniqueness within realm
  const existingBySlug = await findOrganizationBySlug(input.realm_id, slug);
  if (existingBySlug) {
    throw new Error(`Organization with slug "${slug}" already exists in this realm`);
  }

  const record: OrganizationRecord = {
    PK: `ORG#${orgId}`,
    SK: 'METADATA',
    org_id: orgId,
    realm_id: input.realm_id,
    name: input.name,
    slug,
    logo_url: input.logo_url,
    custom_data: input.custom_data,
    settings: input.settings || {},
    status: 'active',
    member_count: 0,
    created_at: now,
    updated_at: now,
    GSI1PK: `REALM#${input.realm_id}`,
    GSI1SK: `ORG#${now}#${orgId}`,
  };

  await dynamoDb.send(new PutCommand({
    TableName: TABLE_NAME,
    Item: record,
    ConditionExpression: 'attribute_not_exists(PK)',
  }));

  return recordToOrganization(record);
}

/**
 * Get organization by ID
 */
export async function getOrganization(orgId: string): Promise<Organization | null> {
  const result = await dynamoDb.send(new GetCommand({
    TableName: TABLE_NAME,
    Key: {
      PK: `ORG#${orgId}`,
      SK: 'METADATA',
    },
  }));

  if (!result.Item) {
    return null;
  }

  return recordToOrganization(result.Item as OrganizationRecord);
}

/**
 * Find organization by slug within a realm
 */
export async function findOrganizationBySlug(
  realmId: string,
  slug: string
): Promise<Organization | null> {
  const result = await dynamoDb.send(new QueryCommand({
    TableName: TABLE_NAME,
    IndexName: 'realm-slug-index',
    KeyConditionExpression: 'realm_id = :realmId AND slug = :slug',
    ExpressionAttributeValues: {
      ':realmId': realmId,
      ':slug': slug,
    },
    Limit: 1,
  }));

  if (!result.Items || result.Items.length === 0) {
    return null;
  }

  return recordToOrganization(result.Items[0] as OrganizationRecord);
}

/**
 * List organizations in a realm
 */
export async function listOrganizations(
  options: OrganizationListOptions
): Promise<OrganizationListResult> {
  const { realm_id, status, limit = 50, cursor } = options;

  let filterExpression: string | undefined;
  const expressionAttributeValues: Record<string, unknown> = {
    ':realmId': `REALM#${realm_id}`,
  };

  if (status) {
    filterExpression = '#status = :status';
    expressionAttributeValues[':status'] = status;
  }

  const result = await dynamoDb.send(new QueryCommand({
    TableName: TABLE_NAME,
    IndexName: 'GSI1',
    KeyConditionExpression: 'GSI1PK = :realmId',
    FilterExpression: filterExpression,
    ExpressionAttributeValues: expressionAttributeValues,
    ExpressionAttributeNames: status ? { '#status': 'status' } : undefined,
    Limit: limit,
    ExclusiveStartKey: cursor ? JSON.parse(Buffer.from(cursor, 'base64').toString()) : undefined,
    ScanIndexForward: false, // Newest first
  }));

  const organizations = (result.Items || []).map(item => 
    recordToOrganization(item as OrganizationRecord)
  );

  return {
    organizations,
    next_cursor: result.LastEvaluatedKey 
      ? Buffer.from(JSON.stringify(result.LastEvaluatedKey)).toString('base64')
      : undefined,
    total_count: organizations.length, // Note: This is page count, not total
  };
}

/**
 * Update organization
 */
export async function updateOrganization(
  orgId: string,
  input: UpdateOrganizationInput
): Promise<Organization | null> {
  const existing = await getOrganization(orgId);
  if (!existing) {
    return null;
  }

  const now = Date.now();
  const updateExpressions: string[] = ['#updatedAt = :updatedAt'];
  const expressionAttributeNames: Record<string, string> = {
    '#updatedAt': 'updated_at',
  };
  const expressionAttributeValues: Record<string, unknown> = {
    ':updatedAt': now,
  };

  if (input.name !== undefined) {
    updateExpressions.push('#name = :name');
    expressionAttributeNames['#name'] = 'name';
    expressionAttributeValues[':name'] = input.name;
  }

  if (input.slug !== undefined) {
    // Check slug uniqueness
    const existingBySlug = await findOrganizationBySlug(existing.realm_id, input.slug);
    if (existingBySlug && existingBySlug.id !== orgId) {
      throw new Error(`Organization with slug "${input.slug}" already exists in this realm`);
    }
    updateExpressions.push('slug = :slug');
    expressionAttributeValues[':slug'] = input.slug;
  }

  if (input.logo_url !== undefined) {
    updateExpressions.push('logo_url = :logoUrl');
    expressionAttributeValues[':logoUrl'] = input.logo_url;
  }

  if (input.custom_data !== undefined) {
    updateExpressions.push('custom_data = :customData');
    expressionAttributeValues[':customData'] = input.custom_data;
  }

  if (input.settings !== undefined) {
    updateExpressions.push('settings = :settings');
    expressionAttributeValues[':settings'] = { ...existing.settings, ...input.settings };
  }

  if (input.status !== undefined) {
    updateExpressions.push('#status = :status');
    expressionAttributeNames['#status'] = 'status';
    expressionAttributeValues[':status'] = input.status;

    if (input.status === 'deleted') {
      updateExpressions.push('deleted_at = :deletedAt');
      expressionAttributeValues[':deletedAt'] = now;
    }
  }

  const result = await dynamoDb.send(new UpdateCommand({
    TableName: TABLE_NAME,
    Key: {
      PK: `ORG#${orgId}`,
      SK: 'METADATA',
    },
    UpdateExpression: `SET ${updateExpressions.join(', ')}`,
    ExpressionAttributeNames: expressionAttributeNames,
    ExpressionAttributeValues: expressionAttributeValues,
    ReturnValues: 'ALL_NEW',
  }));

  if (!result.Attributes) {
    return null;
  }

  return recordToOrganization(result.Attributes as OrganizationRecord);
}

/**
 * Soft delete organization
 */
export async function deleteOrganization(orgId: string): Promise<boolean> {
  const result = await updateOrganization(orgId, { status: 'deleted' });
  return result !== null;
}

/**
 * Hard delete organization (for testing only)
 */
export async function hardDeleteOrganization(orgId: string): Promise<boolean> {
  try {
    await dynamoDb.send(new DeleteCommand({
      TableName: TABLE_NAME,
      Key: {
        PK: `ORG#${orgId}`,
        SK: 'METADATA',
      },
    }));
    return true;
  } catch {
    return false;
  }
}

/**
 * Increment member count
 */
export async function incrementMemberCount(orgId: string, delta: number = 1): Promise<void> {
  await dynamoDb.send(new UpdateCommand({
    TableName: TABLE_NAME,
    Key: {
      PK: `ORG#${orgId}`,
      SK: 'METADATA',
    },
    UpdateExpression: 'SET member_count = if_not_exists(member_count, :zero) + :delta, updated_at = :now',
    ExpressionAttributeValues: {
      ':delta': delta,
      ':zero': 0,
      ':now': Date.now(),
    },
  }));
}

/**
 * Check if organization exists and is active
 */
export async function isOrganizationActive(orgId: string): Promise<boolean> {
  const org = await getOrganization(orgId);
  return org !== null && org.status === 'active';
}
