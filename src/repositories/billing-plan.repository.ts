/**
 * BillingPlan Repository - DynamoDB operations for billing plan configurations
 * 
 * Table: zalt-billing-plans
 * PK: REALM#{realmId}#PLAN#{planId}
 * SK: PLAN
 * GSI: realm-index (realmId -> plans)
 * 
 * Security Requirements:
 * - Stripe integration for payment processing
 * - Audit logging for all billing operations
 * 
 * Validates: Requirements 7.2 (Billing Plans)
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
  BillingPlan,
  BillingPlanStatus,
  BillingPlanResponse,
  CreateBillingPlanInput,
  UpdateBillingPlanInput,
  generateBillingPlanId,
  toBillingPlanResponse,
  isValidBillingPlanType,
  isValidBillingPlanStatus,
  isValidPrice,
  isValidCurrency,
  isValidFeatures,
  isValidLimits,
  isValidPlanName,
  isValidStripePriceId,
  isValidStripeProductId,
  MAX_PLANS_PER_REALM,
  DEFAULT_CURRENCY,
  comparePlansBySortOrder
} from '../models/billing-plan.model';

// Table and index names
const TABLE_NAME = process.env.BILLING_PLANS_TABLE || 'zalt-billing-plans';
const REALM_INDEX = 'realm-index';

// ============================================================================
// Key Generation
// ============================================================================

/**
 * Create composite primary key for billing plan
 */
function createPK(realmId: string, planId: string): string {
  return `REALM#${realmId}#PLAN#${planId}`;
}

/**
 * Create sort key for billing plan
 */
function createSK(): string {
  return 'PLAN';
}

// ============================================================================
// Create Operations
// ============================================================================

/**
 * Create a new billing plan
 */
export async function createBillingPlan(input: CreateBillingPlanInput): Promise<BillingPlan> {
  // Validate name
  if (!isValidPlanName(input.name)) {
    throw new Error('Invalid plan name. Must be 1-100 characters.');
  }
  
  // Validate type
  if (!isValidBillingPlanType(input.type)) {
    throw new Error(`Invalid billing plan type: ${input.type}`);
  }
  
  // Validate prices
  if (!isValidPrice(input.price_monthly)) {
    throw new Error('Invalid monthly price. Must be a non-negative integer in cents.');
  }
  if (!isValidPrice(input.price_yearly)) {
    throw new Error('Invalid yearly price. Must be a non-negative integer in cents.');
  }
  
  // Validate currency
  const currency = input.currency || DEFAULT_CURRENCY;
  if (!isValidCurrency(currency)) {
    throw new Error(`Invalid currency: ${currency}`);
  }
  
  // Validate features
  if (!isValidFeatures(input.features)) {
    throw new Error('Invalid features. Must be an array of non-empty strings.');
  }
  
  // Validate limits
  if (!isValidLimits(input.limits)) {
    throw new Error('Invalid limits. Must be an object with string keys and non-negative integer values.');
  }
  
  // Validate Stripe IDs if provided
  if (input.stripe_price_id_monthly && !isValidStripePriceId(input.stripe_price_id_monthly)) {
    throw new Error('Invalid Stripe monthly price ID format.');
  }
  if (input.stripe_price_id_yearly && !isValidStripePriceId(input.stripe_price_id_yearly)) {
    throw new Error('Invalid Stripe yearly price ID format.');
  }
  if (input.stripe_product_id && !isValidStripeProductId(input.stripe_product_id)) {
    throw new Error('Invalid Stripe product ID format.');
  }
  
  // Check plan limit
  const existingCount = await countBillingPlansByRealm(input.realm_id);
  if (existingCount >= MAX_PLANS_PER_REALM) {
    throw new Error(`Maximum billing plans per realm (${MAX_PLANS_PER_REALM}) exceeded`);
  }
  
  const planId = generateBillingPlanId();
  const now = new Date().toISOString();
  
  const plan: BillingPlan = {
    id: planId,
    realm_id: input.realm_id,
    name: input.name.trim(),
    description: input.description?.trim(),
    type: input.type,
    price_monthly: input.price_monthly,
    price_yearly: input.price_yearly,
    currency: currency.toLowerCase(),
    features: input.features,
    limits: input.limits,
    stripe_price_id_monthly: input.stripe_price_id_monthly,
    stripe_price_id_yearly: input.stripe_price_id_yearly,
    stripe_product_id: input.stripe_product_id,
    status: 'active',
    trial_days: input.trial_days,
    is_default: input.is_default,
    sort_order: input.sort_order,
    metadata: input.metadata,
    created_at: now
  };
  
  // If this is set as default, unset other defaults
  if (input.is_default) {
    await unsetDefaultPlan(input.realm_id);
  }
  
  await dynamoDb.send(new PutCommand({
    TableName: TABLE_NAME,
    Item: {
      pk: createPK(input.realm_id, planId),
      sk: createSK(),
      ...plan
    },
    ConditionExpression: 'attribute_not_exists(pk)'
  }));
  
  return plan;
}

// ============================================================================
// Read Operations
// ============================================================================

/**
 * Get billing plan by ID
 */
export async function getBillingPlanById(
  realmId: string,
  planId: string
): Promise<BillingPlan | null> {
  const result = await dynamoDb.send(new GetCommand({
    TableName: TABLE_NAME,
    Key: {
      pk: createPK(realmId, planId),
      sk: createSK()
    }
  }));
  
  if (!result.Item) {
    return null;
  }
  
  return itemToBillingPlan(result.Item);
}

/**
 * List billing plans for a realm
 */
export async function listBillingPlansByRealm(
  realmId: string,
  options?: {
    status?: BillingPlanStatus;
    limit?: number;
    cursor?: string;
    sortByOrder?: boolean;
  }
): Promise<{ plans: BillingPlanResponse[]; nextCursor?: string }> {
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
      : undefined
  }));
  
  let plans = (result.Items || []).map(item => 
    toBillingPlanResponse(itemToBillingPlan(item))
  );
  
  // Sort by sort_order if requested
  if (options?.sortByOrder) {
    plans = plans.sort((a, b) => {
      const orderA = a.sort_order ?? Number.MAX_SAFE_INTEGER;
      const orderB = b.sort_order ?? Number.MAX_SAFE_INTEGER;
      return orderA - orderB;
    });
  }
  
  return {
    plans,
    nextCursor: result.LastEvaluatedKey
      ? Buffer.from(JSON.stringify(result.LastEvaluatedKey)).toString('base64')
      : undefined
  };
}

/**
 * Get active billing plans for a realm (for pricing table)
 */
export async function getActiveBillingPlans(realmId: string): Promise<BillingPlanResponse[]> {
  const result = await dynamoDb.send(new QueryCommand({
    TableName: TABLE_NAME,
    IndexName: REALM_INDEX,
    KeyConditionExpression: 'realm_id = :realmId',
    FilterExpression: '#status = :active',
    ExpressionAttributeNames: {
      '#status': 'status'
    },
    ExpressionAttributeValues: {
      ':realmId': realmId,
      ':active': 'active'
    }
  }));
  
  const plans = (result.Items || []).map(item => 
    toBillingPlanResponse(itemToBillingPlan(item))
  );
  
  // Sort by sort_order
  return plans.sort((a, b) => {
    const orderA = a.sort_order ?? Number.MAX_SAFE_INTEGER;
    const orderB = b.sort_order ?? Number.MAX_SAFE_INTEGER;
    return orderA - orderB;
  });
}

/**
 * Get default billing plan for a realm
 */
export async function getDefaultBillingPlan(realmId: string): Promise<BillingPlan | null> {
  const result = await dynamoDb.send(new QueryCommand({
    TableName: TABLE_NAME,
    IndexName: REALM_INDEX,
    KeyConditionExpression: 'realm_id = :realmId',
    FilterExpression: '#status = :active AND is_default = :true',
    ExpressionAttributeNames: {
      '#status': 'status'
    },
    ExpressionAttributeValues: {
      ':realmId': realmId,
      ':active': 'active',
      ':true': true
    },
    Limit: 1
  }));
  
  if (!result.Items || result.Items.length === 0) {
    return null;
  }
  
  return itemToBillingPlan(result.Items[0]);
}

/**
 * Count billing plans for a realm
 */
export async function countBillingPlansByRealm(realmId: string): Promise<number> {
  const result = await dynamoDb.send(new QueryCommand({
    TableName: TABLE_NAME,
    IndexName: REALM_INDEX,
    KeyConditionExpression: 'realm_id = :realmId',
    FilterExpression: '#status <> :archived',
    ExpressionAttributeNames: {
      '#status': 'status'
    },
    ExpressionAttributeValues: {
      ':realmId': realmId,
      ':archived': 'archived'
    },
    Select: 'COUNT'
  }));
  
  return result.Count || 0;
}

/**
 * Get billing plan by Stripe price ID
 */
export async function getBillingPlanByStripePriceId(
  realmId: string,
  stripePriceId: string
): Promise<BillingPlan | null> {
  const result = await dynamoDb.send(new QueryCommand({
    TableName: TABLE_NAME,
    IndexName: REALM_INDEX,
    KeyConditionExpression: 'realm_id = :realmId',
    FilterExpression: 'stripe_price_id_monthly = :priceId OR stripe_price_id_yearly = :priceId',
    ExpressionAttributeValues: {
      ':realmId': realmId,
      ':priceId': stripePriceId
    },
    Limit: 1
  }));
  
  if (!result.Items || result.Items.length === 0) {
    return null;
  }
  
  return itemToBillingPlan(result.Items[0]);
}

// ============================================================================
// Update Operations
// ============================================================================

/**
 * Update a billing plan
 */
export async function updateBillingPlan(
  realmId: string,
  planId: string,
  input: UpdateBillingPlanInput
): Promise<BillingPlan | null> {
  // Validate name if provided
  if (input.name !== undefined && !isValidPlanName(input.name)) {
    throw new Error('Invalid plan name. Must be 1-100 characters.');
  }
  
  // Validate type if provided
  if (input.type !== undefined && !isValidBillingPlanType(input.type)) {
    throw new Error(`Invalid billing plan type: ${input.type}`);
  }
  
  // Validate prices if provided
  if (input.price_monthly !== undefined && !isValidPrice(input.price_monthly)) {
    throw new Error('Invalid monthly price. Must be a non-negative integer in cents.');
  }
  if (input.price_yearly !== undefined && !isValidPrice(input.price_yearly)) {
    throw new Error('Invalid yearly price. Must be a non-negative integer in cents.');
  }
  
  // Validate currency if provided
  if (input.currency !== undefined && !isValidCurrency(input.currency)) {
    throw new Error(`Invalid currency: ${input.currency}`);
  }
  
  // Validate features if provided
  if (input.features !== undefined && !isValidFeatures(input.features)) {
    throw new Error('Invalid features. Must be an array of non-empty strings.');
  }
  
  // Validate limits if provided
  if (input.limits !== undefined && !isValidLimits(input.limits)) {
    throw new Error('Invalid limits. Must be an object with string keys and non-negative integer values.');
  }
  
  // Validate status if provided
  if (input.status !== undefined && !isValidBillingPlanStatus(input.status)) {
    throw new Error(`Invalid billing plan status: ${input.status}`);
  }
  
  // Validate Stripe IDs if provided
  if (input.stripe_price_id_monthly && !isValidStripePriceId(input.stripe_price_id_monthly)) {
    throw new Error('Invalid Stripe monthly price ID format.');
  }
  if (input.stripe_price_id_yearly && !isValidStripePriceId(input.stripe_price_id_yearly)) {
    throw new Error('Invalid Stripe yearly price ID format.');
  }
  if (input.stripe_product_id && !isValidStripeProductId(input.stripe_product_id)) {
    throw new Error('Invalid Stripe product ID format.');
  }
  
  const now = new Date().toISOString();
  
  // Build update expression dynamically
  const updateParts: string[] = ['updated_at = :now'];
  const expressionAttributeValues: Record<string, unknown> = {
    ':now': now
  };
  const expressionAttributeNames: Record<string, string> = {};
  
  if (input.name !== undefined) {
    updateParts.push('#name = :name');
    expressionAttributeValues[':name'] = input.name.trim();
    expressionAttributeNames['#name'] = 'name';
  }
  
  if (input.description !== undefined) {
    updateParts.push('description = :description');
    expressionAttributeValues[':description'] = input.description?.trim();
  }
  
  if (input.type !== undefined) {
    updateParts.push('#type = :type');
    expressionAttributeValues[':type'] = input.type;
    expressionAttributeNames['#type'] = 'type';
  }
  
  if (input.price_monthly !== undefined) {
    updateParts.push('price_monthly = :price_monthly');
    expressionAttributeValues[':price_monthly'] = input.price_monthly;
  }
  
  if (input.price_yearly !== undefined) {
    updateParts.push('price_yearly = :price_yearly');
    expressionAttributeValues[':price_yearly'] = input.price_yearly;
  }
  
  if (input.currency !== undefined) {
    updateParts.push('currency = :currency');
    expressionAttributeValues[':currency'] = input.currency.toLowerCase();
  }
  
  if (input.features !== undefined) {
    updateParts.push('features = :features');
    expressionAttributeValues[':features'] = input.features;
  }
  
  if (input.limits !== undefined) {
    updateParts.push('limits = :limits');
    expressionAttributeValues[':limits'] = input.limits;
  }
  
  if (input.stripe_price_id_monthly !== undefined) {
    updateParts.push('stripe_price_id_monthly = :stripe_price_id_monthly');
    expressionAttributeValues[':stripe_price_id_monthly'] = input.stripe_price_id_monthly;
  }
  
  if (input.stripe_price_id_yearly !== undefined) {
    updateParts.push('stripe_price_id_yearly = :stripe_price_id_yearly');
    expressionAttributeValues[':stripe_price_id_yearly'] = input.stripe_price_id_yearly;
  }
  
  if (input.stripe_product_id !== undefined) {
    updateParts.push('stripe_product_id = :stripe_product_id');
    expressionAttributeValues[':stripe_product_id'] = input.stripe_product_id;
  }
  
  if (input.status !== undefined) {
    updateParts.push('#status = :status');
    expressionAttributeValues[':status'] = input.status;
    expressionAttributeNames['#status'] = 'status';
  }
  
  if (input.trial_days !== undefined) {
    updateParts.push('trial_days = :trial_days');
    expressionAttributeValues[':trial_days'] = input.trial_days;
  }
  
  if (input.is_default !== undefined) {
    updateParts.push('is_default = :is_default');
    expressionAttributeValues[':is_default'] = input.is_default;
    
    // If setting as default, unset other defaults first
    if (input.is_default) {
      await unsetDefaultPlan(realmId, planId);
    }
  }
  
  if (input.sort_order !== undefined) {
    updateParts.push('sort_order = :sort_order');
    expressionAttributeValues[':sort_order'] = input.sort_order;
  }
  
  if (input.metadata !== undefined) {
    updateParts.push('metadata = :metadata');
    expressionAttributeValues[':metadata'] = input.metadata;
  }
  
  try {
    const result = await dynamoDb.send(new UpdateCommand({
      TableName: TABLE_NAME,
      Key: {
        pk: createPK(realmId, planId),
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
    
    return itemToBillingPlan(result.Attributes);
  } catch (error: unknown) {
    if ((error as { name?: string }).name === 'ConditionalCheckFailedException') {
      return null;
    }
    throw error;
  }
}

/**
 * Update billing plan status
 */
export async function updateBillingPlanStatus(
  realmId: string,
  planId: string,
  status: BillingPlanStatus
): Promise<BillingPlan | null> {
  return updateBillingPlan(realmId, planId, { status });
}

/**
 * Set a plan as the default plan for a realm
 */
export async function setDefaultBillingPlan(
  realmId: string,
  planId: string
): Promise<BillingPlan | null> {
  // First unset any existing default
  await unsetDefaultPlan(realmId, planId);
  
  // Then set this plan as default (skip the unset in updateBillingPlan by using internal update)
  const now = new Date().toISOString();
  
  try {
    const result = await dynamoDb.send(new UpdateCommand({
      TableName: TABLE_NAME,
      Key: {
        pk: createPK(realmId, planId),
        sk: createSK()
      },
      UpdateExpression: 'SET is_default = :is_default, updated_at = :now',
      ExpressionAttributeValues: {
        ':is_default': true,
        ':now': now
      },
      ConditionExpression: 'attribute_exists(pk)',
      ReturnValues: 'ALL_NEW'
    }));
    
    if (!result.Attributes) {
      return null;
    }
    
    return itemToBillingPlan(result.Attributes);
  } catch (error: unknown) {
    if ((error as { name?: string }).name === 'ConditionalCheckFailedException') {
      return null;
    }
    throw error;
  }
}

/**
 * Unset default plan for a realm (except for excludePlanId)
 */
async function unsetDefaultPlan(realmId: string, excludePlanId?: string): Promise<void> {
  const { plans } = await listBillingPlansByRealm(realmId, { limit: 100 });
  
  for (const plan of plans) {
    if (plan.is_default && plan.id !== excludePlanId) {
      await dynamoDb.send(new UpdateCommand({
        TableName: TABLE_NAME,
        Key: {
          pk: createPK(realmId, plan.id),
          sk: createSK()
        },
        UpdateExpression: 'SET is_default = :false, updated_at = :now',
        ExpressionAttributeValues: {
          ':false': false,
          ':now': new Date().toISOString()
        }
      }));
    }
  }
}

// ============================================================================
// Delete Operations
// ============================================================================

/**
 * Archive a billing plan (soft delete)
 */
export async function archiveBillingPlan(
  realmId: string,
  planId: string
): Promise<boolean> {
  const result = await updateBillingPlanStatus(realmId, planId, 'archived');
  return result !== null;
}

/**
 * Hard delete a billing plan permanently
 */
export async function hardDeleteBillingPlan(
  realmId: string,
  planId: string
): Promise<boolean> {
  try {
    await dynamoDb.send(new DeleteCommand({
      TableName: TABLE_NAME,
      Key: {
        pk: createPK(realmId, planId),
        sk: createSK()
      }
    }));
    return true;
  } catch {
    return false;
  }
}

/**
 * Delete all billing plans for a realm
 * Used when deleting a realm
 */
export async function deleteAllRealmBillingPlans(realmId: string): Promise<number> {
  const { plans } = await listBillingPlansByRealm(realmId, { limit: 1000 });
  
  if (plans.length === 0) {
    return 0;
  }
  
  // Batch delete (max 25 items per batch)
  const batches: BillingPlanResponse[][] = [];
  for (let i = 0; i < plans.length; i += 25) {
    batches.push(plans.slice(i, i + 25));
  }
  
  let deletedCount = 0;
  
  for (const batch of batches) {
    try {
      await dynamoDb.send(new BatchWriteCommand({
        RequestItems: {
          [TABLE_NAME]: batch.map(plan => ({
            DeleteRequest: {
              Key: {
                pk: createPK(realmId, plan.id),
                sk: createSK()
              }
            }
          }))
        }
      }));
      deletedCount += batch.length;
    } catch (error) {
      console.error('Failed to delete billing plan batch:', error);
    }
  }
  
  return deletedCount;
}

// ============================================================================
// Statistics
// ============================================================================

/**
 * Count billing plans by status for a realm
 */
export async function countBillingPlansByStatus(
  realmId: string
): Promise<Record<BillingPlanStatus, number>> {
  const counts: Record<BillingPlanStatus, number> = {
    active: 0,
    inactive: 0,
    archived: 0
  };
  
  const { plans } = await listBillingPlansByRealm(realmId, { limit: 1000 });
  
  for (const plan of plans) {
    counts[plan.status]++;
  }
  
  return counts;
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Convert DynamoDB item to BillingPlan
 */
function itemToBillingPlan(item: Record<string, unknown>): BillingPlan {
  return {
    id: item.id as string,
    realm_id: item.realm_id as string,
    name: item.name as string,
    description: item.description as string | undefined,
    type: item.type as BillingPlan['type'],
    price_monthly: item.price_monthly as number,
    price_yearly: item.price_yearly as number,
    currency: item.currency as string,
    features: item.features as string[],
    limits: item.limits as Record<string, number>,
    stripe_price_id_monthly: item.stripe_price_id_monthly as string | undefined,
    stripe_price_id_yearly: item.stripe_price_id_yearly as string | undefined,
    stripe_product_id: item.stripe_product_id as string | undefined,
    status: item.status as BillingPlanStatus,
    trial_days: item.trial_days as number | undefined,
    is_default: item.is_default as boolean | undefined,
    sort_order: item.sort_order as number | undefined,
    metadata: item.metadata as BillingPlan['metadata'],
    created_at: item.created_at as string,
    updated_at: item.updated_at as string | undefined
  };
}
