/**
 * Webhook Repository - DynamoDB operations for webhook configurations
 * 
 * Table: zalt-webhooks
 * PK: REALM#{realmId}#WEBHOOK#{webhookId}
 * SK: WEBHOOK
 * GSI: realm-index (realmId -> webhooks)
 * 
 * Security Requirements:
 * - Secret must be cryptographically secure (32 bytes, hex encoded)
 * - Payload must be signed with HMAC-SHA256
 * - Audit logging for all operations
 * 
 * Validates: Requirements 12.1 (Webhook System)
 */

import {
  GetCommand,
  PutCommand,
  UpdateCommand,
  QueryCommand,
  DeleteCommand,
  BatchWriteCommand
} from '@aws-sdk/lib-dynamodb';
import { dynamoDb } from '../services/dynamodb.service';
import {
  Webhook,
  WebhookStatus,
  WebhookEventType,
  WebhookResponse,
  WebhookWithSecret,
  CreateWebhookInput,
  UpdateWebhookInput,
  generateWebhookId,
  generateWebhookSecret,
  toWebhookResponse,
  isValidWebhookUrl,
  isValidWebhookEvent,
  MAX_WEBHOOKS_PER_REALM
} from '../models/webhook.model';

// Table and index names
const TABLE_NAME = process.env.WEBHOOKS_TABLE || 'zalt-webhooks';
const REALM_INDEX = 'realm-index';

// ============================================================================
// Key Generation
// ============================================================================

/**
 * Create composite primary key for webhook
 */
function createPK(realmId: string, webhookId: string): string {
  return `REALM#${realmId}#WEBHOOK#${webhookId}`;
}

/**
 * Create sort key for webhook
 */
function createSK(): string {
  return 'WEBHOOK';
}

// ============================================================================
// Create Operations
// ============================================================================

/**
 * Create a new webhook
 * Returns the webhook with the raw secret (only time secret is available)
 * 
 * Security: Secret is stored as-is but only returned once on creation
 */
export async function createWebhook(input: CreateWebhookInput): Promise<WebhookWithSecret> {
  // Validate URL
  if (!isValidWebhookUrl(input.url)) {
    throw new Error('Invalid webhook URL. Must be HTTPS.');
  }
  
  // Validate events
  for (const event of input.events) {
    if (!isValidWebhookEvent(event)) {
      throw new Error(`Invalid webhook event: ${event}`);
    }
  }
  
  // Check webhook limit
  const existingCount = await countWebhooksByRealm(input.realm_id);
  if (existingCount >= MAX_WEBHOOKS_PER_REALM) {
    throw new Error(`Maximum webhooks per realm (${MAX_WEBHOOKS_PER_REALM}) exceeded`);
  }
  
  const webhookId = generateWebhookId();
  const secret = generateWebhookSecret();
  const now = new Date().toISOString();
  
  const webhook: Webhook = {
    id: webhookId,
    realm_id: input.realm_id,
    url: input.url,
    secret,
    events: input.events,
    status: 'active',
    description: input.description,
    created_at: now,
    metadata: {
      created_by: input.created_by,
      failure_count: 0,
      total_deliveries: 0,
      successful_deliveries: 0
    }
  };
  
  await dynamoDb.send(new PutCommand({
    TableName: TABLE_NAME,
    Item: {
      pk: createPK(input.realm_id, webhookId),
      sk: createSK(),
      // Entity data
      ...webhook
    },
    ConditionExpression: 'attribute_not_exists(pk)'
  }));
  
  return {
    webhook: toWebhookResponse(webhook),
    secret
  };
}

// ============================================================================
// Read Operations
// ============================================================================

/**
 * Get webhook by ID
 */
export async function getWebhookById(
  realmId: string,
  webhookId: string
): Promise<Webhook | null> {
  const result = await dynamoDb.send(new GetCommand({
    TableName: TABLE_NAME,
    Key: {
      pk: createPK(realmId, webhookId),
      sk: createSK()
    }
  }));
  
  if (!result.Item) {
    return null;
  }
  
  return itemToWebhook(result.Item);
}

/**
 * List webhooks for a realm
 */
export async function listWebhooksByRealm(
  realmId: string,
  options?: {
    status?: WebhookStatus;
    limit?: number;
    cursor?: string;
  }
): Promise<{ webhooks: WebhookResponse[]; nextCursor?: string }> {
  const limit = options?.limit || 50;
  
  let filterExpression: string | undefined;
  const expressionAttributeValues: Record<string, unknown> = {
    ':realmId': realmId
  };
  const expressionAttributeNames: Record<string, string> = {};
  
  if (options?.status) {
    filterExpression = '#status = :status';
    expressionAttributeValues[':status'] = options.status;
    expressionAttributeNames['#status'] = 'status';
  }
  
  const result = await dynamoDb.send(new QueryCommand({
    TableName: TABLE_NAME,
    IndexName: REALM_INDEX,
    KeyConditionExpression: 'realm_id = :realmId',
    FilterExpression: filterExpression,
    ExpressionAttributeNames: Object.keys(expressionAttributeNames).length > 0 
      ? expressionAttributeNames 
      : undefined,
    ExpressionAttributeValues: expressionAttributeValues,
    Limit: limit,
    ExclusiveStartKey: options?.cursor 
      ? JSON.parse(Buffer.from(options.cursor, 'base64').toString())
      : undefined,
    ScanIndexForward: false // Newest first
  }));
  
  const webhooks = (result.Items || []).map(item => 
    toWebhookResponse(itemToWebhook(item))
  );
  
  return {
    webhooks,
    nextCursor: result.LastEvaluatedKey
      ? Buffer.from(JSON.stringify(result.LastEvaluatedKey)).toString('base64')
      : undefined
  };
}

/**
 * Get active webhooks for a realm that subscribe to a specific event
 */
export async function getWebhooksForEvent(
  realmId: string,
  eventType: WebhookEventType
): Promise<Webhook[]> {
  const result = await dynamoDb.send(new QueryCommand({
    TableName: TABLE_NAME,
    IndexName: REALM_INDEX,
    KeyConditionExpression: 'realm_id = :realmId',
    FilterExpression: '#status = :active AND contains(events, :eventType)',
    ExpressionAttributeNames: {
      '#status': 'status'
    },
    ExpressionAttributeValues: {
      ':realmId': realmId,
      ':active': 'active',
      ':eventType': eventType
    }
  }));
  
  return (result.Items || []).map(item => itemToWebhook(item));
}

/**
 * Count webhooks for a realm
 */
export async function countWebhooksByRealm(realmId: string): Promise<number> {
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

// ============================================================================
// Update Operations
// ============================================================================

/**
 * Update a webhook
 */
export async function updateWebhook(
  realmId: string,
  webhookId: string,
  input: UpdateWebhookInput
): Promise<Webhook | null> {
  // Validate URL if provided
  if (input.url && !isValidWebhookUrl(input.url)) {
    throw new Error('Invalid webhook URL. Must be HTTPS.');
  }
  
  // Validate events if provided
  if (input.events) {
    for (const event of input.events) {
      if (!isValidWebhookEvent(event)) {
        throw new Error(`Invalid webhook event: ${event}`);
      }
    }
  }
  
  const now = new Date().toISOString();
  
  // Build update expression dynamically
  const updateParts: string[] = ['updated_at = :now'];
  const expressionAttributeValues: Record<string, unknown> = {
    ':now': now
  };
  const expressionAttributeNames: Record<string, string> = {};
  
  if (input.url !== undefined) {
    updateParts.push('#url = :url');
    expressionAttributeValues[':url'] = input.url;
    expressionAttributeNames['#url'] = 'url';
  }
  
  if (input.events !== undefined) {
    updateParts.push('events = :events');
    expressionAttributeValues[':events'] = input.events;
  }
  
  if (input.status !== undefined) {
    updateParts.push('#status = :status');
    expressionAttributeValues[':status'] = input.status;
    expressionAttributeNames['#status'] = 'status';
  }
  
  if (input.description !== undefined) {
    updateParts.push('description = :description');
    expressionAttributeValues[':description'] = input.description;
  }
  
  try {
    const result = await dynamoDb.send(new UpdateCommand({
      TableName: TABLE_NAME,
      Key: {
        pk: createPK(realmId, webhookId),
        sk: createSK()
      },
      UpdateExpression: `SET ${updateParts.join(', ')}`,
      ExpressionAttributeNames: Object.keys(expressionAttributeNames).length > 0 
        ? expressionAttributeNames 
        : undefined,
      ExpressionAttributeValues: expressionAttributeValues,
      ConditionExpression: 'attribute_exists(pk)',
      ReturnValues: 'ALL_NEW'
    }));
    
    if (!result.Attributes) {
      return null;
    }
    
    return itemToWebhook(result.Attributes);
  } catch (error: unknown) {
    if ((error as { name?: string }).name === 'ConditionalCheckFailedException') {
      return null;
    }
    throw error;
  }
}

/**
 * Update webhook status
 */
export async function updateWebhookStatus(
  realmId: string,
  webhookId: string,
  status: WebhookStatus
): Promise<Webhook | null> {
  return updateWebhook(realmId, webhookId, { status });
}

/**
 * Rotate webhook secret
 * Generates a new secret and returns it (only time new secret is available)
 */
export async function rotateWebhookSecret(
  realmId: string,
  webhookId: string
): Promise<WebhookWithSecret | null> {
  const newSecret = generateWebhookSecret();
  const now = new Date().toISOString();
  
  try {
    const result = await dynamoDb.send(new UpdateCommand({
      TableName: TABLE_NAME,
      Key: {
        pk: createPK(realmId, webhookId),
        sk: createSK()
      },
      UpdateExpression: 'SET secret = :secret, updated_at = :now',
      ExpressionAttributeValues: {
        ':secret': newSecret,
        ':now': now
      },
      ConditionExpression: 'attribute_exists(pk)',
      ReturnValues: 'ALL_NEW'
    }));
    
    if (!result.Attributes) {
      return null;
    }
    
    const webhook = itemToWebhook(result.Attributes);
    return {
      webhook: toWebhookResponse(webhook),
      secret: newSecret
    };
  } catch (error: unknown) {
    if ((error as { name?: string }).name === 'ConditionalCheckFailedException') {
      return null;
    }
    throw error;
  }
}

/**
 * Record webhook delivery attempt
 */
export async function recordDeliveryAttempt(
  realmId: string,
  webhookId: string,
  success: boolean,
  failureReason?: string
): Promise<void> {
  const now = new Date().toISOString();
  
  const updateParts: string[] = [
    'metadata.total_deliveries = if_not_exists(metadata.total_deliveries, :zero) + :one'
  ];
  const expressionAttributeValues: Record<string, unknown> = {
    ':zero': 0,
    ':one': 1
  };
  
  if (success) {
    updateParts.push('metadata.successful_deliveries = if_not_exists(metadata.successful_deliveries, :zero) + :one');
    updateParts.push('metadata.failure_count = :zero');
    updateParts.push('last_triggered_at = :now');
    expressionAttributeValues[':now'] = now;
  } else {
    updateParts.push('metadata.failure_count = if_not_exists(metadata.failure_count, :zero) + :one');
    updateParts.push('metadata.last_failure_at = :failureAt');
    updateParts.push('metadata.last_failure_reason = :failureReason');
    expressionAttributeValues[':failureAt'] = now;
    expressionAttributeValues[':failureReason'] = failureReason || 'Unknown error';
  }
  
  try {
    await dynamoDb.send(new UpdateCommand({
      TableName: TABLE_NAME,
      Key: {
        pk: createPK(realmId, webhookId),
        sk: createSK()
      },
      UpdateExpression: `SET ${updateParts.join(', ')}`,
      ExpressionAttributeValues: expressionAttributeValues,
      ConditionExpression: 'attribute_exists(pk)'
    }));
  } catch (error: unknown) {
    // Log but don't throw - delivery recording is not critical
    console.error('Failed to record webhook delivery attempt:', error);
  }
}

// ============================================================================
// Delete Operations
// ============================================================================

/**
 * Soft delete a webhook (mark as deleted)
 */
export async function deleteWebhook(
  realmId: string,
  webhookId: string
): Promise<boolean> {
  const result = await updateWebhookStatus(realmId, webhookId, 'deleted');
  return result !== null;
}

/**
 * Hard delete a webhook permanently
 */
export async function hardDeleteWebhook(
  realmId: string,
  webhookId: string
): Promise<boolean> {
  try {
    await dynamoDb.send(new DeleteCommand({
      TableName: TABLE_NAME,
      Key: {
        pk: createPK(realmId, webhookId),
        sk: createSK()
      }
    }));
    return true;
  } catch {
    return false;
  }
}

/**
 * Delete all webhooks for a realm
 * Used when deleting a realm
 */
export async function deleteAllRealmWebhooks(realmId: string): Promise<number> {
  const { webhooks } = await listWebhooksByRealm(realmId, { limit: 1000 });
  
  if (webhooks.length === 0) {
    return 0;
  }
  
  // Batch delete (max 25 items per batch)
  const batches: WebhookResponse[][] = [];
  for (let i = 0; i < webhooks.length; i += 25) {
    batches.push(webhooks.slice(i, i + 25));
  }
  
  let deletedCount = 0;
  
  for (const batch of batches) {
    try {
      await dynamoDb.send(new BatchWriteCommand({
        RequestItems: {
          [TABLE_NAME]: batch.map(webhook => ({
            DeleteRequest: {
              Key: {
                pk: createPK(realmId, webhook.id),
                sk: createSK()
              }
            }
          }))
        }
      }));
      deletedCount += batch.length;
    } catch (error) {
      console.error('Failed to delete webhook batch:', error);
    }
  }
  
  return deletedCount;
}

// ============================================================================
// Statistics
// ============================================================================

/**
 * Count webhooks by status for a realm
 */
export async function countWebhooksByStatus(
  realmId: string
): Promise<Record<WebhookStatus, number>> {
  const counts: Record<WebhookStatus, number> = {
    active: 0,
    inactive: 0,
    deleted: 0
  };
  
  const { webhooks } = await listWebhooksByRealm(realmId, { limit: 1000 });
  
  for (const webhook of webhooks) {
    counts[webhook.status]++;
  }
  
  return counts;
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Convert DynamoDB item to Webhook
 */
function itemToWebhook(item: Record<string, unknown>): Webhook {
  return {
    id: item.id as string,
    realm_id: item.realm_id as string,
    url: item.url as string,
    secret: item.secret as string,
    events: item.events as WebhookEventType[],
    status: item.status as WebhookStatus,
    description: item.description as string | undefined,
    created_at: item.created_at as string,
    updated_at: item.updated_at as string | undefined,
    last_triggered_at: item.last_triggered_at as string | undefined,
    metadata: item.metadata as Webhook['metadata']
  };
}
