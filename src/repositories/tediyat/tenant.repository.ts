/**
 * Tediyat Tenant Repository - DynamoDB operations for tenants
 * Validates: Requirements 9.1, 9.5
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
  Tenant,
  TenantDynamoDBItem,
  CreateTenantInput,
  UpdateTenantInput,
  TenantStatus,
  generateTenantId,
  generateSlug,
} from '../../models/tediyat/tenant.model';

const TABLE_NAME = process.env.TEDIYAT_TABLE || 'zalt-tediyat';
const REALM_ID = 'tediyat';

/**
 * Convert DynamoDB item to Tenant
 */
function itemToTenant(item: TenantDynamoDBItem): Tenant {
  return {
    id: item.id,
    realm_id: item.realm_id,
    name: item.name,
    slug: item.slug,
    logo_url: item.logo_url,
    metadata: item.metadata,
    settings: item.settings,
    status: item.status,
    member_count: item.member_count,
    created_at: item.created_at,
    updated_at: item.updated_at,
    created_by: item.created_by,
  };
}

/**
 * Create a new tenant
 */
export async function createTenant(input: CreateTenantInput): Promise<Tenant> {
  const now = new Date().toISOString();
  const tenantId = generateTenantId();
  const slug = input.slug || generateSlug(input.name);

  // Check slug uniqueness
  const existingBySlug = await findTenantBySlug(slug);
  if (existingBySlug) {
    throw new Error(`Tenant with slug "${slug}" already exists`);
  }

  const item: TenantDynamoDBItem = {
    PK: `TENANT#${tenantId}`,
    SK: 'METADATA',
    GSI1PK: `REALM#${REALM_ID}#TENANTS`,
    GSI1SK: `TENANT#${tenantId}`,
    GSI2PK: `SLUG#${slug}`,
    GSI2SK: 'TENANT',
    GSI3PK: `OWNER#${input.created_by}`,
    GSI3SK: `TENANT#${tenantId}`,
    
    id: tenantId,
    realm_id: REALM_ID,
    name: input.name,
    slug,
    logo_url: input.logo_url,
    metadata: input.metadata,
    settings: input.settings,
    status: 'active',
    member_count: 1, // Owner is first member
    created_at: now,
    updated_at: now,
    created_by: input.created_by,
    entity_type: 'TENANT',
  };

  await dynamoDb.send(new PutCommand({
    TableName: TABLE_NAME,
    Item: item,
    ConditionExpression: 'attribute_not_exists(PK)',
  }));

  return itemToTenant(item);
}

/**
 * Get tenant by ID
 */
export async function getTenant(tenantId: string): Promise<Tenant | null> {
  const result = await dynamoDb.send(new GetCommand({
    TableName: TABLE_NAME,
    Key: {
      PK: `TENANT#${tenantId}`,
      SK: 'METADATA',
    },
  }));

  if (!result.Item) {
    return null;
  }

  return itemToTenant(result.Item as TenantDynamoDBItem);
}

/**
 * Find tenant by slug
 */
export async function findTenantBySlug(slug: string): Promise<Tenant | null> {
  const result = await dynamoDb.send(new QueryCommand({
    TableName: TABLE_NAME,
    IndexName: 'GSI2',
    KeyConditionExpression: 'GSI2PK = :slugPk AND GSI2SK = :sk',
    ExpressionAttributeValues: {
      ':slugPk': `SLUG#${slug}`,
      ':sk': 'TENANT',
    },
    Limit: 1,
  }));

  if (!result.Items || result.Items.length === 0) {
    return null;
  }

  return itemToTenant(result.Items[0] as TenantDynamoDBItem);
}

/**
 * List tenants owned by a user
 */
export async function listTenantsByOwner(
  userId: string,
  limit: number = 50,
  cursor?: string
): Promise<{ tenants: Tenant[]; nextCursor?: string }> {
  const result = await dynamoDb.send(new QueryCommand({
    TableName: TABLE_NAME,
    IndexName: 'GSI3',
    KeyConditionExpression: 'GSI3PK = :ownerPk',
    FilterExpression: '#status = :active',
    ExpressionAttributeNames: {
      '#status': 'status',
    },
    ExpressionAttributeValues: {
      ':ownerPk': `OWNER#${userId}`,
      ':active': 'active',
    },
    Limit: limit,
    ExclusiveStartKey: cursor ? JSON.parse(Buffer.from(cursor, 'base64').toString()) : undefined,
  }));

  const tenants = (result.Items || []).map(item => 
    itemToTenant(item as TenantDynamoDBItem)
  );

  return {
    tenants,
    nextCursor: result.LastEvaluatedKey 
      ? Buffer.from(JSON.stringify(result.LastEvaluatedKey)).toString('base64')
      : undefined,
  };
}

/**
 * Update tenant
 */
export async function updateTenant(
  tenantId: string,
  input: UpdateTenantInput
): Promise<Tenant | null> {
  const existing = await getTenant(tenantId);
  if (!existing) {
    return null;
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

  if (input.logo_url !== undefined) {
    updateExpressions.push('logo_url = :logoUrl');
    expressionAttributeValues[':logoUrl'] = input.logo_url;
  }

  if (input.metadata !== undefined) {
    updateExpressions.push('metadata = :metadata');
    expressionAttributeValues[':metadata'] = { ...existing.metadata, ...input.metadata };
  }

  if (input.settings !== undefined) {
    updateExpressions.push('settings = :settings');
    expressionAttributeValues[':settings'] = { ...existing.settings, ...input.settings };
  }

  if (input.status !== undefined) {
    updateExpressions.push('#status = :status');
    expressionAttributeNames['#status'] = 'status';
    expressionAttributeValues[':status'] = input.status;
  }

  const result = await dynamoDb.send(new UpdateCommand({
    TableName: TABLE_NAME,
    Key: {
      PK: `TENANT#${tenantId}`,
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

  return itemToTenant(result.Attributes as TenantDynamoDBItem);
}

/**
 * Soft delete tenant
 */
export async function deleteTenant(tenantId: string): Promise<boolean> {
  const result = await updateTenant(tenantId, { status: 'deleted' });
  return result !== null;
}

/**
 * Hard delete tenant (for testing only)
 */
export async function hardDeleteTenant(tenantId: string): Promise<boolean> {
  try {
    await dynamoDb.send(new DeleteCommand({
      TableName: TABLE_NAME,
      Key: {
        PK: `TENANT#${tenantId}`,
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
export async function incrementMemberCount(tenantId: string, delta: number = 1): Promise<void> {
  await dynamoDb.send(new UpdateCommand({
    TableName: TABLE_NAME,
    Key: {
      PK: `TENANT#${tenantId}`,
      SK: 'METADATA',
    },
    UpdateExpression: 'SET member_count = if_not_exists(member_count, :zero) + :delta, updated_at = :now',
    ExpressionAttributeValues: {
      ':delta': delta,
      ':zero': 0,
      ':now': new Date().toISOString(),
    },
  }));
}

/**
 * Check if tenant exists and is active
 */
export async function isTenantActive(tenantId: string): Promise<boolean> {
  const tenant = await getTenant(tenantId);
  return tenant !== null && tenant.status === 'active';
}

/**
 * Check if slug is available
 */
export async function isSlugAvailable(slug: string): Promise<boolean> {
  const existing = await findTenantBySlug(slug);
  return existing === null;
}
