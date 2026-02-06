/**
 * Subscription Repository - DynamoDB operations for tenant subscriptions
 * 
 * Table: zalt-subscriptions
 * PK: TENANT#{tenantId}#SUBSCRIPTION#{subscriptionId}
 * SK: SUBSCRIPTION
 * GSI: stripe-index (stripeSubscriptionId -> subscriptionId)
 * GSI: tenant-index (tenantId -> subscriptions)
 * 
 * Security Requirements:
 * - Stripe integration for payment processing
 * - Audit logging for all subscription operations
 * 
 * Validates: Requirements 7.4 (Subscriptions)
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
  Subscription,
  SubscriptionStatus,
  SubscriptionResponse,
  CreateSubscriptionInput,
  UpdateSubscriptionInput,
  generateSubscriptionId,
  toSubscriptionResponse,
  isValidSubscriptionStatus,
  isValidStripeSubscriptionId,
  isValidStripeCustomerId,
  isValidISODate,
  isValidTenantId,
  isValidPlanId,
  isValidQuantity,
  MAX_SUBSCRIPTIONS_PER_TENANT
} from '../models/subscription.model';

// Table and index names
const TABLE_NAME = process.env.SUBSCRIPTIONS_TABLE || 'zalt-subscriptions';
const STRIPE_INDEX = 'stripe-index';
const TENANT_INDEX = 'tenant-index';

// ============================================================================
// Key Generation
// ============================================================================

/**
 * Create composite primary key for subscription
 */
function createPK(tenantId: string, subscriptionId: string): string {
  return `TENANT#${tenantId}#SUBSCRIPTION#${subscriptionId}`;
}

/**
 * Create sort key for subscription
 */
function createSK(): string {
  return 'SUBSCRIPTION';
}

// ============================================================================
// Create Operations
// ============================================================================

/**
 * Create a new subscription
 */
export async function createSubscription(input: CreateSubscriptionInput): Promise<Subscription> {
  // Validate tenant ID
  if (!isValidTenantId(input.tenant_id)) {
    throw new Error('Invalid tenant ID. Must be a non-empty string.');
  }
  
  // Validate plan ID
  if (!isValidPlanId(input.plan_id)) {
    throw new Error('Invalid plan ID format. Must match plan_xxx format.');
  }
  
  // Validate Stripe subscription ID
  if (!isValidStripeSubscriptionId(input.stripe_subscription_id)) {
    throw new Error('Invalid Stripe subscription ID format. Must start with sub_.');
  }
  
  // Validate Stripe customer ID if provided
  if (input.stripe_customer_id && !isValidStripeCustomerId(input.stripe_customer_id)) {
    throw new Error('Invalid Stripe customer ID format. Must start with cus_.');
  }
  
  // Validate status
  if (!isValidSubscriptionStatus(input.status)) {
    throw new Error(`Invalid subscription status: ${input.status}`);
  }
  
  // Validate dates
  if (!isValidISODate(input.current_period_start)) {
    throw new Error('Invalid current_period_start. Must be a valid ISO 8601 date.');
  }
  if (!isValidISODate(input.current_period_end)) {
    throw new Error('Invalid current_period_end. Must be a valid ISO 8601 date.');
  }
  
  // Validate trial dates if provided
  if (input.trial_start && !isValidISODate(input.trial_start)) {
    throw new Error('Invalid trial_start. Must be a valid ISO 8601 date.');
  }
  if (input.trial_end && !isValidISODate(input.trial_end)) {
    throw new Error('Invalid trial_end. Must be a valid ISO 8601 date.');
  }
  
  // Validate quantity if provided
  if (input.quantity !== undefined && !isValidQuantity(input.quantity)) {
    throw new Error('Invalid quantity. Must be a positive integer up to 100,000.');
  }
  
  // Check subscription limit
  const existingCount = await countSubscriptionsByTenant(input.tenant_id);
  if (existingCount >= MAX_SUBSCRIPTIONS_PER_TENANT) {
    throw new Error(`Maximum subscriptions per tenant (${MAX_SUBSCRIPTIONS_PER_TENANT}) exceeded`);
  }
  
  // Check for duplicate Stripe subscription ID
  const existingByStripe = await getSubscriptionByStripeId(input.stripe_subscription_id);
  if (existingByStripe) {
    throw new Error('A subscription with this Stripe subscription ID already exists.');
  }
  
  const subscriptionId = generateSubscriptionId();
  const now = new Date().toISOString();
  
  const subscription: Subscription = {
    id: subscriptionId,
    tenant_id: input.tenant_id,
    plan_id: input.plan_id,
    stripe_subscription_id: input.stripe_subscription_id,
    stripe_customer_id: input.stripe_customer_id,
    status: input.status,
    current_period_start: input.current_period_start,
    current_period_end: input.current_period_end,
    cancel_at_period_end: input.cancel_at_period_end,
    trial_start: input.trial_start,
    trial_end: input.trial_end,
    quantity: input.quantity,
    metadata: input.metadata,
    created_at: now
  };
  
  await dynamoDb.send(new PutCommand({
    TableName: TABLE_NAME,
    Item: {
      pk: createPK(input.tenant_id, subscriptionId),
      sk: createSK(),
      ...subscription
    },
    ConditionExpression: 'attribute_not_exists(pk)'
  }));
  
  return subscription;
}

// ============================================================================
// Read Operations
// ============================================================================

/**
 * Get subscription by ID
 */
export async function getSubscriptionById(
  tenantId: string,
  subscriptionId: string
): Promise<Subscription | null> {
  const result = await dynamoDb.send(new GetCommand({
    TableName: TABLE_NAME,
    Key: {
      pk: createPK(tenantId, subscriptionId),
      sk: createSK()
    }
  }));
  
  if (!result.Item) {
    return null;
  }
  
  return itemToSubscription(result.Item);
}

/**
 * Get subscription by Stripe subscription ID
 */
export async function getSubscriptionByStripeId(
  stripeSubscriptionId: string
): Promise<Subscription | null> {
  const result = await dynamoDb.send(new QueryCommand({
    TableName: TABLE_NAME,
    IndexName: STRIPE_INDEX,
    KeyConditionExpression: 'stripe_subscription_id = :stripeId',
    ExpressionAttributeValues: {
      ':stripeId': stripeSubscriptionId
    },
    Limit: 1
  }));
  
  if (!result.Items || result.Items.length === 0) {
    return null;
  }
  
  return itemToSubscription(result.Items[0]);
}

/**
 * List subscriptions for a tenant
 */
export async function listSubscriptionsByTenant(
  tenantId: string,
  options?: {
    status?: SubscriptionStatus;
    limit?: number;
    cursor?: string;
  }
): Promise<{ subscriptions: SubscriptionResponse[]; nextCursor?: string }> {
  const limit = options?.limit || 50;
  
  let filterExpression: string | undefined;
  const expressionAttributeValues: Record<string, unknown> = {
    ':tenantId': tenantId
  };
  const expressionAttributeNames: Record<string, string> = {};
  
  if (options?.status) {
    filterExpression = '#status = :status';
    expressionAttributeValues[':status'] = options.status;
    expressionAttributeNames['#status'] = 'status';
  }
  
  const result = await dynamoDb.send(new QueryCommand({
    TableName: TABLE_NAME,
    IndexName: TENANT_INDEX,
    KeyConditionExpression: 'tenant_id = :tenantId',
    FilterExpression: filterExpression,
    ExpressionAttributeNames: Object.keys(expressionAttributeNames).length > 0 
      ? expressionAttributeNames 
      : undefined,
    ExpressionAttributeValues: expressionAttributeValues,
    Limit: limit,
    ExclusiveStartKey: options?.cursor 
      ? JSON.parse(Buffer.from(options.cursor, 'base64').toString())
      : undefined
  }));
  
  const subscriptions = (result.Items || [])
    .map(item => toSubscriptionResponse(itemToSubscription(item)))
    .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
  
  return {
    subscriptions,
    nextCursor: result.LastEvaluatedKey
      ? Buffer.from(JSON.stringify(result.LastEvaluatedKey)).toString('base64')
      : undefined
  };
}

/**
 * Get active subscription for a tenant
 */
export async function getActiveSubscription(tenantId: string): Promise<Subscription | null> {
  const result = await dynamoDb.send(new QueryCommand({
    TableName: TABLE_NAME,
    IndexName: TENANT_INDEX,
    KeyConditionExpression: 'tenant_id = :tenantId',
    FilterExpression: '#status IN (:active, :trialing)',
    ExpressionAttributeNames: {
      '#status': 'status'
    },
    ExpressionAttributeValues: {
      ':tenantId': tenantId,
      ':active': 'active',
      ':trialing': 'trialing'
    },
    Limit: 1
  }));
  
  if (!result.Items || result.Items.length === 0) {
    return null;
  }
  
  return itemToSubscription(result.Items[0]);
}

/**
 * Count subscriptions for a tenant
 */
export async function countSubscriptionsByTenant(tenantId: string): Promise<number> {
  const result = await dynamoDb.send(new QueryCommand({
    TableName: TABLE_NAME,
    IndexName: TENANT_INDEX,
    KeyConditionExpression: 'tenant_id = :tenantId',
    FilterExpression: '#status <> :canceled',
    ExpressionAttributeNames: {
      '#status': 'status'
    },
    ExpressionAttributeValues: {
      ':tenantId': tenantId,
      ':canceled': 'canceled'
    },
    Select: 'COUNT'
  }));
  
  return result.Count || 0;
}

/**
 * Get subscriptions by plan ID
 */
export async function getSubscriptionsByPlanId(
  planId: string,
  options?: {
    status?: SubscriptionStatus;
    limit?: number;
  }
): Promise<Subscription[]> {
  // Note: This requires a full table scan - consider adding a GSI for plan_id if frequently used
  const limit = options?.limit || 100;
  
  let filterExpression = 'plan_id = :planId';
  const expressionAttributeValues: Record<string, unknown> = {
    ':planId': planId
  };
  const expressionAttributeNames: Record<string, string> = {};
  
  if (options?.status) {
    filterExpression += ' AND #status = :status';
    expressionAttributeValues[':status'] = options.status;
    expressionAttributeNames['#status'] = 'status';
  }
  
  const result = await dynamoDb.send(new QueryCommand({
    TableName: TABLE_NAME,
    FilterExpression: filterExpression,
    ExpressionAttributeNames: Object.keys(expressionAttributeNames).length > 0 
      ? expressionAttributeNames 
      : undefined,
    ExpressionAttributeValues: expressionAttributeValues,
    Limit: limit
  }));
  
  return (result.Items || []).map(item => itemToSubscription(item));
}

// ============================================================================
// Update Operations
// ============================================================================

/**
 * Update a subscription
 */
export async function updateSubscription(
  tenantId: string,
  subscriptionId: string,
  input: UpdateSubscriptionInput
): Promise<Subscription | null> {
  // Validate plan ID if provided
  if (input.plan_id !== undefined && !isValidPlanId(input.plan_id)) {
    throw new Error('Invalid plan ID format. Must match plan_xxx format.');
  }
  
  // Validate status if provided
  if (input.status !== undefined && !isValidSubscriptionStatus(input.status)) {
    throw new Error(`Invalid subscription status: ${input.status}`);
  }
  
  // Validate dates if provided
  if (input.current_period_start !== undefined && !isValidISODate(input.current_period_start)) {
    throw new Error('Invalid current_period_start. Must be a valid ISO 8601 date.');
  }
  if (input.current_period_end !== undefined && !isValidISODate(input.current_period_end)) {
    throw new Error('Invalid current_period_end. Must be a valid ISO 8601 date.');
  }
  if (input.canceled_at !== undefined && input.canceled_at !== null && !isValidISODate(input.canceled_at)) {
    throw new Error('Invalid canceled_at. Must be a valid ISO 8601 date.');
  }
  if (input.trial_start !== undefined && input.trial_start !== null && !isValidISODate(input.trial_start)) {
    throw new Error('Invalid trial_start. Must be a valid ISO 8601 date.');
  }
  if (input.trial_end !== undefined && input.trial_end !== null && !isValidISODate(input.trial_end)) {
    throw new Error('Invalid trial_end. Must be a valid ISO 8601 date.');
  }
  
  // Validate quantity if provided
  if (input.quantity !== undefined && !isValidQuantity(input.quantity)) {
    throw new Error('Invalid quantity. Must be a positive integer up to 100,000.');
  }
  
  const now = new Date().toISOString();
  
  // Build update expression dynamically
  const updateParts: string[] = ['updated_at = :now'];
  const expressionAttributeValues: Record<string, unknown> = {
    ':now': now
  };
  const expressionAttributeNames: Record<string, string> = {};
  
  if (input.plan_id !== undefined) {
    updateParts.push('plan_id = :plan_id');
    expressionAttributeValues[':plan_id'] = input.plan_id;
  }
  
  if (input.status !== undefined) {
    updateParts.push('#status = :status');
    expressionAttributeValues[':status'] = input.status;
    expressionAttributeNames['#status'] = 'status';
  }
  
  if (input.current_period_start !== undefined) {
    updateParts.push('current_period_start = :current_period_start');
    expressionAttributeValues[':current_period_start'] = input.current_period_start;
  }
  
  if (input.current_period_end !== undefined) {
    updateParts.push('current_period_end = :current_period_end');
    expressionAttributeValues[':current_period_end'] = input.current_period_end;
  }
  
  if (input.cancel_at_period_end !== undefined) {
    updateParts.push('cancel_at_period_end = :cancel_at_period_end');
    expressionAttributeValues[':cancel_at_period_end'] = input.cancel_at_period_end;
  }
  
  if (input.canceled_at !== undefined) {
    updateParts.push('canceled_at = :canceled_at');
    expressionAttributeValues[':canceled_at'] = input.canceled_at;
  }
  
  if (input.trial_start !== undefined) {
    updateParts.push('trial_start = :trial_start');
    expressionAttributeValues[':trial_start'] = input.trial_start;
  }
  
  if (input.trial_end !== undefined) {
    updateParts.push('trial_end = :trial_end');
    expressionAttributeValues[':trial_end'] = input.trial_end;
  }
  
  if (input.quantity !== undefined) {
    updateParts.push('quantity = :quantity');
    expressionAttributeValues[':quantity'] = input.quantity;
  }
  
  if (input.metadata !== undefined) {
    updateParts.push('metadata = :metadata');
    expressionAttributeValues[':metadata'] = input.metadata;
  }
  
  try {
    const result = await dynamoDb.send(new UpdateCommand({
      TableName: TABLE_NAME,
      Key: {
        pk: createPK(tenantId, subscriptionId),
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
    
    return itemToSubscription(result.Attributes);
  } catch (error: unknown) {
    if ((error as { name?: string }).name === 'ConditionalCheckFailedException') {
      return null;
    }
    throw error;
  }
}

/**
 * Update subscription status
 */
export async function updateSubscriptionStatus(
  tenantId: string,
  subscriptionId: string,
  status: SubscriptionStatus
): Promise<Subscription | null> {
  const updateInput: UpdateSubscriptionInput = { status };
  
  // If canceling, set canceled_at
  if (status === 'canceled') {
    updateInput.canceled_at = new Date().toISOString();
  }
  
  return updateSubscription(tenantId, subscriptionId, updateInput);
}

/**
 * Update subscription by Stripe ID (for webhook handling)
 */
export async function updateSubscriptionByStripeId(
  stripeSubscriptionId: string,
  input: UpdateSubscriptionInput
): Promise<Subscription | null> {
  const subscription = await getSubscriptionByStripeId(stripeSubscriptionId);
  if (!subscription) {
    return null;
  }
  
  return updateSubscription(subscription.tenant_id, subscription.id, input);
}

/**
 * Cancel subscription at period end
 */
export async function cancelSubscriptionAtPeriodEnd(
  tenantId: string,
  subscriptionId: string
): Promise<Subscription | null> {
  return updateSubscription(tenantId, subscriptionId, {
    cancel_at_period_end: true
  });
}

/**
 * Reactivate subscription (undo cancel at period end)
 */
export async function reactivateSubscription(
  tenantId: string,
  subscriptionId: string
): Promise<Subscription | null> {
  return updateSubscription(tenantId, subscriptionId, {
    cancel_at_period_end: false,
    canceled_at: undefined
  });
}

/**
 * Update subscription period (for renewals)
 */
export async function updateSubscriptionPeriod(
  tenantId: string,
  subscriptionId: string,
  periodStart: string,
  periodEnd: string
): Promise<Subscription | null> {
  return updateSubscription(tenantId, subscriptionId, {
    current_period_start: periodStart,
    current_period_end: periodEnd,
    status: 'active'
  });
}

// ============================================================================
// Delete Operations
// ============================================================================

/**
 * Delete a subscription (hard delete)
 */
export async function deleteSubscription(
  tenantId: string,
  subscriptionId: string
): Promise<boolean> {
  try {
    await dynamoDb.send(new DeleteCommand({
      TableName: TABLE_NAME,
      Key: {
        pk: createPK(tenantId, subscriptionId),
        sk: createSK()
      }
    }));
    return true;
  } catch {
    return false;
  }
}

/**
 * Delete all subscriptions for a tenant
 * Used when deleting a tenant
 */
export async function deleteAllTenantSubscriptions(tenantId: string): Promise<number> {
  const { subscriptions } = await listSubscriptionsByTenant(tenantId, { limit: 1000 });
  
  if (subscriptions.length === 0) {
    return 0;
  }
  
  // Batch delete (max 25 items per batch)
  const batches: SubscriptionResponse[][] = [];
  for (let i = 0; i < subscriptions.length; i += 25) {
    batches.push(subscriptions.slice(i, i + 25));
  }
  
  let deletedCount = 0;
  
  for (const batch of batches) {
    try {
      await dynamoDb.send(new BatchWriteCommand({
        RequestItems: {
          [TABLE_NAME]: batch.map(sub => ({
            DeleteRequest: {
              Key: {
                pk: createPK(tenantId, sub.id),
                sk: createSK()
              }
            }
          }))
        }
      }));
      deletedCount += batch.length;
    } catch (error) {
      console.error('Failed to delete subscription batch:', error);
    }
  }
  
  return deletedCount;
}

// ============================================================================
// Statistics
// ============================================================================

/**
 * Count subscriptions by status for a tenant
 */
export async function countSubscriptionsByStatus(
  tenantId: string
): Promise<Record<SubscriptionStatus, number>> {
  const counts: Record<SubscriptionStatus, number> = {
    active: 0,
    past_due: 0,
    canceled: 0,
    trialing: 0
  };
  
  const { subscriptions } = await listSubscriptionsByTenant(tenantId, { limit: 1000 });
  
  for (const sub of subscriptions) {
    counts[sub.status]++;
  }
  
  return counts;
}

/**
 * Get subscription statistics for analytics
 */
export async function getSubscriptionStats(tenantId: string): Promise<{
  total: number;
  active: number;
  trialing: number;
  past_due: number;
  canceled: number;
}> {
  const counts = await countSubscriptionsByStatus(tenantId);
  
  return {
    total: counts.active + counts.trialing + counts.past_due + counts.canceled,
    active: counts.active,
    trialing: counts.trialing,
    past_due: counts.past_due,
    canceled: counts.canceled
  };
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Convert DynamoDB item to Subscription
 */
function itemToSubscription(item: Record<string, unknown>): Subscription {
  return {
    id: item.id as string,
    tenant_id: item.tenant_id as string,
    plan_id: item.plan_id as string,
    stripe_subscription_id: item.stripe_subscription_id as string,
    stripe_customer_id: item.stripe_customer_id as string | undefined,
    status: item.status as SubscriptionStatus,
    current_period_start: item.current_period_start as string,
    current_period_end: item.current_period_end as string,
    cancel_at_period_end: item.cancel_at_period_end as boolean | undefined,
    canceled_at: item.canceled_at as string | undefined,
    trial_start: item.trial_start as string | undefined,
    trial_end: item.trial_end as string | undefined,
    quantity: item.quantity as number | undefined,
    metadata: item.metadata as Subscription['metadata'],
    created_at: item.created_at as string,
    updated_at: item.updated_at as string | undefined
  };
}
