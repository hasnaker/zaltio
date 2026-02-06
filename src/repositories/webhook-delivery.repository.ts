/**
 * WebhookDelivery Repository - DynamoDB operations for webhook delivery tracking
 * 
 * Table: zalt-webhook-deliveries
 * PK: WEBHOOK#{webhookId}#DELIVERY#{deliveryId}
 * SK: DELIVERY#{timestamp}
 * GSI: webhook-index (webhookId -> deliveries)
 * 
 * Security Requirements:
 * - Payload must be stored securely
 * - Error messages must not leak sensitive information
 * - Audit logging for all delivery attempts
 * 
 * Validates: Requirements 12.7 (Webhook Delivery Logs)
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
  WebhookDelivery,
  WebhookDeliveryResponse,
  DeliveryStatus,
  CreateWebhookDeliveryInput,
  UpdateWebhookDeliveryInput,
  DeliveryAttemptResult,
  generateDeliveryId,
  calculateNextRetryAt,
  determineDeliveryStatus,
  toWebhookDeliveryResponse,
  createWebhookDeliveryFromInput,
  isValidDeliveryStatus,
  truncateResponseBody,
  sanitizeErrorMessage,
  DEFAULT_MAX_ATTEMPTS,
  MAX_DELIVERIES_PER_QUERY
} from '../models/webhook-delivery.model';

// Table and index names
const TABLE_NAME = process.env.WEBHOOK_DELIVERIES_TABLE || 'zalt-webhook-deliveries';
const WEBHOOK_INDEX = 'webhook-index';

// ============================================================================
// Key Generation
// ============================================================================

/**
 * Create composite primary key for webhook delivery
 */
function createPK(webhookId: string, deliveryId: string): string {
  return `WEBHOOK#${webhookId}#DELIVERY#${deliveryId}`;
}

/**
 * Create sort key for webhook delivery
 */
function createSK(timestamp: string): string {
  return `DELIVERY#${timestamp}`;
}

// ============================================================================
// Create Operations
// ============================================================================

/**
 * Create a new webhook delivery record
 * 
 * @param input - Delivery creation input
 * @returns The created webhook delivery
 */
export async function createWebhookDelivery(
  input: CreateWebhookDeliveryInput
): Promise<WebhookDelivery> {
  const delivery = createWebhookDeliveryFromInput(input);
  
  await dynamoDb.send(new PutCommand({
    TableName: TABLE_NAME,
    Item: {
      pk: createPK(input.webhook_id, delivery.id),
      sk: createSK(delivery.created_at),
      // Entity data (webhook_id is already in delivery)
      ...delivery
    },
    ConditionExpression: 'attribute_not_exists(pk)'
  }));
  
  return delivery;
}

// ============================================================================
// Read Operations
// ============================================================================

/**
 * Get webhook delivery by ID
 * 
 * @param webhookId - Parent webhook ID
 * @param deliveryId - Delivery ID
 * @returns The webhook delivery or null if not found
 */
export async function getWebhookDeliveryById(
  webhookId: string,
  deliveryId: string
): Promise<WebhookDelivery | null> {
  // We need to query by pk prefix since we don't know the exact timestamp
  const result = await dynamoDb.send(new QueryCommand({
    TableName: TABLE_NAME,
    KeyConditionExpression: 'pk = :pk',
    ExpressionAttributeValues: {
      ':pk': createPK(webhookId, deliveryId)
    },
    Limit: 1
  }));
  
  if (!result.Items || result.Items.length === 0) {
    return null;
  }
  
  return itemToWebhookDelivery(result.Items[0]);
}

/**
 * List webhook deliveries for a webhook
 * 
 * @param webhookId - Parent webhook ID
 * @param options - Query options
 * @returns List of deliveries with pagination cursor
 */
export async function listWebhookDeliveries(
  webhookId: string,
  options?: {
    status?: DeliveryStatus;
    limit?: number;
    cursor?: string;
    startDate?: string;
    endDate?: string;
  }
): Promise<{ deliveries: WebhookDeliveryResponse[]; nextCursor?: string }> {
  const limit = Math.min(options?.limit || 50, MAX_DELIVERIES_PER_QUERY);
  
  let filterExpression: string | undefined;
  const expressionAttributeValues: Record<string, unknown> = {
    ':webhookId': webhookId
  };
  const expressionAttributeNames: Record<string, string> = {};
  
  const filterParts: string[] = [];
  
  if (options?.status) {
    if (!isValidDeliveryStatus(options.status)) {
      throw new Error(`Invalid delivery status: ${options.status}`);
    }
    filterParts.push('#status = :status');
    expressionAttributeValues[':status'] = options.status;
    expressionAttributeNames['#status'] = 'status';
  }
  
  if (options?.startDate) {
    filterParts.push('created_at >= :startDate');
    expressionAttributeValues[':startDate'] = options.startDate;
  }
  
  if (options?.endDate) {
    filterParts.push('created_at <= :endDate');
    expressionAttributeValues[':endDate'] = options.endDate;
  }
  
  if (filterParts.length > 0) {
    filterExpression = filterParts.join(' AND ');
  }
  
  const result = await dynamoDb.send(new QueryCommand({
    TableName: TABLE_NAME,
    IndexName: WEBHOOK_INDEX,
    KeyConditionExpression: 'webhook_id = :webhookId',
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
  
  const deliveries = (result.Items || []).map(item => 
    toWebhookDeliveryResponse(itemToWebhookDelivery(item))
  );
  
  return {
    deliveries,
    nextCursor: result.LastEvaluatedKey
      ? Buffer.from(JSON.stringify(result.LastEvaluatedKey)).toString('base64')
      : undefined
  };
}

/**
 * Get pending deliveries ready for retry
 * 
 * @param webhookId - Parent webhook ID
 * @param limit - Maximum number of deliveries to return
 * @returns List of deliveries ready for retry
 */
export async function getPendingDeliveries(
  webhookId: string,
  limit: number = 10
): Promise<WebhookDelivery[]> {
  const now = new Date().toISOString();
  
  const result = await dynamoDb.send(new QueryCommand({
    TableName: TABLE_NAME,
    IndexName: WEBHOOK_INDEX,
    KeyConditionExpression: 'webhook_id = :webhookId',
    FilterExpression: '(#status = :pending OR (#status = :retrying AND (attribute_not_exists(next_retry_at) OR next_retry_at <= :now)))',
    ExpressionAttributeNames: {
      '#status': 'status'
    },
    ExpressionAttributeValues: {
      ':webhookId': webhookId,
      ':pending': 'pending',
      ':retrying': 'retrying',
      ':now': now
    },
    Limit: limit
  }));
  
  return (result.Items || []).map(item => itemToWebhookDelivery(item));
}

/**
 * Get recent deliveries for a webhook (last N deliveries)
 * 
 * @param webhookId - Parent webhook ID
 * @param limit - Number of recent deliveries to return
 * @returns List of recent deliveries
 */
export async function getRecentDeliveries(
  webhookId: string,
  limit: number = 100
): Promise<WebhookDeliveryResponse[]> {
  const result = await listWebhookDeliveries(webhookId, { limit });
  return result.deliveries;
}

/**
 * Count deliveries by status for a webhook
 * 
 * @param webhookId - Parent webhook ID
 * @returns Count of deliveries by status
 */
export async function countDeliveriesByStatus(
  webhookId: string
): Promise<Record<DeliveryStatus, number>> {
  const counts: Record<DeliveryStatus, number> = {
    pending: 0,
    success: 0,
    failed: 0,
    retrying: 0
  };
  
  // Query all deliveries (with pagination for large datasets)
  let cursor: string | undefined;
  
  do {
    const result = await listWebhookDeliveries(webhookId, { 
      limit: MAX_DELIVERIES_PER_QUERY,
      cursor 
    });
    
    for (const delivery of result.deliveries) {
      counts[delivery.status]++;
    }
    
    cursor = result.nextCursor;
  } while (cursor);
  
  return counts;
}

// ============================================================================
// Update Operations
// ============================================================================

/**
 * Update a webhook delivery
 * 
 * @param webhookId - Parent webhook ID
 * @param deliveryId - Delivery ID
 * @param input - Update input
 * @returns Updated delivery or null if not found
 */
export async function updateWebhookDelivery(
  webhookId: string,
  deliveryId: string,
  input: UpdateWebhookDeliveryInput
): Promise<WebhookDelivery | null> {
  // First, get the delivery to find the exact SK
  const existing = await getWebhookDeliveryById(webhookId, deliveryId);
  if (!existing) {
    return null;
  }
  
  const now = new Date().toISOString();
  
  // Build update expression dynamically
  const updateParts: string[] = ['updated_at = :now'];
  const expressionAttributeValues: Record<string, unknown> = {
    ':now': now
  };
  const expressionAttributeNames: Record<string, string> = {};
  
  if (input.status !== undefined) {
    if (!isValidDeliveryStatus(input.status)) {
      throw new Error(`Invalid delivery status: ${input.status}`);
    }
    updateParts.push('#status = :status');
    expressionAttributeValues[':status'] = input.status;
    expressionAttributeNames['#status'] = 'status';
  }
  
  if (input.attempts !== undefined) {
    updateParts.push('attempts = :attempts');
    expressionAttributeValues[':attempts'] = input.attempts;
  }
  
  if (input.response_code !== undefined) {
    updateParts.push('response_code = :responseCode');
    expressionAttributeValues[':responseCode'] = input.response_code;
  }
  
  if (input.response_time_ms !== undefined) {
    updateParts.push('response_time_ms = :responseTimeMs');
    expressionAttributeValues[':responseTimeMs'] = input.response_time_ms;
  }
  
  if (input.error !== undefined) {
    updateParts.push('#error = :error');
    expressionAttributeValues[':error'] = input.error;
    expressionAttributeNames['#error'] = 'error';
  }
  
  if (input.next_retry_at !== undefined) {
    updateParts.push('next_retry_at = :nextRetryAt');
    expressionAttributeValues[':nextRetryAt'] = input.next_retry_at;
  }
  
  if (input.completed_at !== undefined) {
    updateParts.push('completed_at = :completedAt');
    expressionAttributeValues[':completedAt'] = input.completed_at;
  }
  
  if (input.metadata !== undefined) {
    updateParts.push('metadata = :metadata');
    expressionAttributeValues[':metadata'] = {
      ...existing.metadata,
      ...input.metadata
    };
  }
  
  try {
    const result = await dynamoDb.send(new UpdateCommand({
      TableName: TABLE_NAME,
      Key: {
        pk: createPK(webhookId, deliveryId),
        sk: createSK(existing.created_at)
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
    
    return itemToWebhookDelivery(result.Attributes);
  } catch (error: unknown) {
    if ((error as { name?: string }).name === 'ConditionalCheckFailedException') {
      return null;
    }
    throw error;
  }
}

/**
 * Record a delivery attempt result
 * 
 * @param webhookId - Parent webhook ID
 * @param deliveryId - Delivery ID
 * @param result - The delivery attempt result
 * @returns Updated delivery or null if not found
 */
export async function recordDeliveryAttempt(
  webhookId: string,
  deliveryId: string,
  result: DeliveryAttemptResult
): Promise<WebhookDelivery | null> {
  const existing = await getWebhookDeliveryById(webhookId, deliveryId);
  if (!existing) {
    return null;
  }
  
  const newAttempts = existing.attempts + 1;
  const newStatus = determineDeliveryStatus(result, newAttempts, existing.max_attempts);
  const now = new Date().toISOString();
  
  const updateInput: UpdateWebhookDeliveryInput = {
    status: newStatus,
    attempts: newAttempts,
    response_code: result.response_code,
    response_time_ms: result.response_time_ms
  };
  
  if (result.error) {
    updateInput.error = sanitizeErrorMessage(result.error);
  }
  
  // Set next retry time if retrying
  if (newStatus === 'retrying') {
    updateInput.next_retry_at = calculateNextRetryAt(newAttempts) || undefined;
  }
  
  // Set completion time if complete
  if (newStatus === 'success' || newStatus === 'failed') {
    updateInput.completed_at = now;
  }
  
  // Update metadata with response details
  if (result.response_body || result.response_headers) {
    updateInput.metadata = {
      response_body: result.response_body 
        ? truncateResponseBody(result.response_body) 
        : undefined,
      response_headers: result.response_headers
    };
  }
  
  return updateWebhookDelivery(webhookId, deliveryId, updateInput);
}

/**
 * Mark delivery as success
 * 
 * @param webhookId - Parent webhook ID
 * @param deliveryId - Delivery ID
 * @param responseCode - HTTP response code
 * @param responseTimeMs - Response time in milliseconds
 * @returns Updated delivery or null if not found
 */
export async function markDeliverySuccess(
  webhookId: string,
  deliveryId: string,
  responseCode: number,
  responseTimeMs: number
): Promise<WebhookDelivery | null> {
  return recordDeliveryAttempt(webhookId, deliveryId, {
    success: true,
    response_code: responseCode,
    response_time_ms: responseTimeMs
  });
}

/**
 * Mark delivery as failed
 * 
 * @param webhookId - Parent webhook ID
 * @param deliveryId - Delivery ID
 * @param error - Error message
 * @param responseCode - HTTP response code (optional)
 * @returns Updated delivery or null if not found
 */
export async function markDeliveryFailed(
  webhookId: string,
  deliveryId: string,
  error: string,
  responseCode?: number
): Promise<WebhookDelivery | null> {
  return recordDeliveryAttempt(webhookId, deliveryId, {
    success: false,
    error,
    response_code: responseCode
  });
}

/**
 * Increment delivery attempt count (for retry tracking)
 * 
 * @param webhookId - Parent webhook ID
 * @param deliveryId - Delivery ID
 * @param error - Error message from failed attempt
 * @returns Updated delivery or null if not found
 */
export async function incrementDeliveryAttempt(
  webhookId: string,
  deliveryId: string,
  error: string
): Promise<WebhookDelivery | null> {
  return recordDeliveryAttempt(webhookId, deliveryId, {
    success: false,
    error
  });
}

// ============================================================================
// Delete Operations
// ============================================================================

/**
 * Delete a webhook delivery
 * 
 * @param webhookId - Parent webhook ID
 * @param deliveryId - Delivery ID
 * @returns True if deleted, false if not found
 */
export async function deleteWebhookDelivery(
  webhookId: string,
  deliveryId: string
): Promise<boolean> {
  // First, get the delivery to find the exact SK
  const existing = await getWebhookDeliveryById(webhookId, deliveryId);
  if (!existing) {
    return false;
  }
  
  try {
    await dynamoDb.send(new DeleteCommand({
      TableName: TABLE_NAME,
      Key: {
        pk: createPK(webhookId, deliveryId),
        sk: createSK(existing.created_at)
      }
    }));
    return true;
  } catch {
    return false;
  }
}

/**
 * Delete all deliveries for a webhook
 * Used when deleting a webhook
 * 
 * @param webhookId - Parent webhook ID
 * @returns Number of deleted deliveries
 */
export async function deleteAllWebhookDeliveries(webhookId: string): Promise<number> {
  let deletedCount = 0;
  let cursor: string | undefined;
  
  do {
    // Get batch of deliveries
    const result = await dynamoDb.send(new QueryCommand({
      TableName: TABLE_NAME,
      IndexName: WEBHOOK_INDEX,
      KeyConditionExpression: 'webhook_id = :webhookId',
      ExpressionAttributeValues: {
        ':webhookId': webhookId
      },
      Limit: 25, // DynamoDB batch limit
      ExclusiveStartKey: cursor 
        ? JSON.parse(Buffer.from(cursor, 'base64').toString())
        : undefined
    }));
    
    const items = result.Items || [];
    
    if (items.length === 0) {
      break;
    }
    
    // Batch delete
    try {
      await dynamoDb.send(new BatchWriteCommand({
        RequestItems: {
          [TABLE_NAME]: items.map(item => ({
            DeleteRequest: {
              Key: {
                pk: item.pk as string,
                sk: item.sk as string
              }
            }
          }))
        }
      }));
      deletedCount += items.length;
    } catch (error) {
      console.error('Failed to delete delivery batch:', error);
    }
    
    cursor = result.LastEvaluatedKey
      ? Buffer.from(JSON.stringify(result.LastEvaluatedKey)).toString('base64')
      : undefined;
  } while (cursor);
  
  return deletedCount;
}

/**
 * Delete old deliveries (cleanup job)
 * 
 * @param webhookId - Parent webhook ID
 * @param olderThan - Delete deliveries older than this date
 * @returns Number of deleted deliveries
 */
export async function deleteOldDeliveries(
  webhookId: string,
  olderThan: string
): Promise<number> {
  let deletedCount = 0;
  let cursor: string | undefined;
  
  do {
    // Get batch of old deliveries
    const result = await dynamoDb.send(new QueryCommand({
      TableName: TABLE_NAME,
      IndexName: WEBHOOK_INDEX,
      KeyConditionExpression: 'webhook_id = :webhookId',
      FilterExpression: 'created_at < :olderThan',
      ExpressionAttributeValues: {
        ':webhookId': webhookId,
        ':olderThan': olderThan
      },
      Limit: 25,
      ExclusiveStartKey: cursor 
        ? JSON.parse(Buffer.from(cursor, 'base64').toString())
        : undefined
    }));
    
    const items = result.Items || [];
    
    if (items.length === 0) {
      break;
    }
    
    // Batch delete
    try {
      await dynamoDb.send(new BatchWriteCommand({
        RequestItems: {
          [TABLE_NAME]: items.map(item => ({
            DeleteRequest: {
              Key: {
                pk: item.pk as string,
                sk: item.sk as string
              }
            }
          }))
        }
      }));
      deletedCount += items.length;
    } catch (error) {
      console.error('Failed to delete old delivery batch:', error);
    }
    
    cursor = result.LastEvaluatedKey
      ? Buffer.from(JSON.stringify(result.LastEvaluatedKey)).toString('base64')
      : undefined;
  } while (cursor);
  
  return deletedCount;
}

// ============================================================================
// Statistics
// ============================================================================

/**
 * Get delivery statistics for a webhook
 * 
 * @param webhookId - Parent webhook ID
 * @param options - Query options
 * @returns Delivery statistics
 */
export async function getDeliveryStats(
  webhookId: string,
  options?: {
    startDate?: string;
    endDate?: string;
  }
): Promise<{
  total: number;
  pending: number;
  success: number;
  failed: number;
  retrying: number;
  averageResponseTime: number | null;
  successRate: number;
}> {
  const stats = {
    total: 0,
    pending: 0,
    success: 0,
    failed: 0,
    retrying: 0,
    averageResponseTime: null as number | null,
    successRate: 0
  };
  
  let totalResponseTime = 0;
  let responseTimeCount = 0;
  let cursor: string | undefined;
  
  do {
    const result = await listWebhookDeliveries(webhookId, {
      limit: MAX_DELIVERIES_PER_QUERY,
      cursor,
      startDate: options?.startDate,
      endDate: options?.endDate
    });
    
    for (const delivery of result.deliveries) {
      stats.total++;
      stats[delivery.status]++;
      
      if (delivery.response_time_ms !== undefined) {
        totalResponseTime += delivery.response_time_ms;
        responseTimeCount++;
      }
    }
    
    cursor = result.nextCursor;
  } while (cursor);
  
  if (responseTimeCount > 0) {
    stats.averageResponseTime = Math.round(totalResponseTime / responseTimeCount);
  }
  
  const completed = stats.success + stats.failed;
  if (completed > 0) {
    stats.successRate = Math.round((stats.success / completed) * 100);
  }
  
  return stats;
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Convert DynamoDB item to WebhookDelivery
 */
function itemToWebhookDelivery(item: Record<string, unknown>): WebhookDelivery {
  return {
    id: item.id as string,
    webhook_id: item.webhook_id as string,
    event_type: item.event_type as string,
    payload: item.payload as WebhookDelivery['payload'],
    status: item.status as DeliveryStatus,
    attempts: item.attempts as number,
    max_attempts: (item.max_attempts as number) || DEFAULT_MAX_ATTEMPTS,
    response_code: item.response_code as number | undefined,
    response_time_ms: item.response_time_ms as number | undefined,
    error: item.error as string | undefined,
    next_retry_at: item.next_retry_at as string | undefined,
    created_at: item.created_at as string,
    updated_at: item.updated_at as string | undefined,
    completed_at: item.completed_at as string | undefined,
    metadata: item.metadata as WebhookDelivery['metadata']
  };
}
