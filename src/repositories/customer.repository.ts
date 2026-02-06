/**
 * Customer Repository - DynamoDB operations for platform customers
 * Table: zalt-customers
 * PK: CUSTOMER#{customer_id}
 * GSI: email-index (email → customer_id)
 * 
 * Validates: Requirements 1.2, 1.5 (Customer account system)
 */

import { 
  GetCommand, 
  PutCommand, 
  UpdateCommand, 
  QueryCommand,
  DeleteCommand
} from '@aws-sdk/lib-dynamodb';
import { dynamoDb } from '../services/dynamodb.service';
import { 
  Customer, 
  CreateCustomerInput, 
  CustomerPlan,
  PLAN_LIMITS,
  DEFAULT_CUSTOMER_BILLING
} from '../models/customer.model';
import { hashPassword } from '../utils/password';
import { v4 as uuidv4 } from 'uuid';

const TABLE_NAME = 'zalt-customers';
const EMAIL_INDEX = 'email-index';

/**
 * Generate customer ID with prefix
 */
function generateCustomerId(): string {
  return `customer_${uuidv4().replace(/-/g, '').substring(0, 24)}`;
}

/**
 * Create a new customer
 */
export async function createCustomer(input: CreateCustomerInput): Promise<Customer> {
  const customerId = generateCustomerId();
  const now = new Date().toISOString();
  const plan: CustomerPlan = input.plan || 'free';
  
  // Hash password with Argon2id (32MB memory, timeCost 5)
  const passwordHash = await hashPassword(input.password);
  
  const customer: Customer = {
    id: customerId,
    email: input.email.toLowerCase().trim(),
    email_verified: false,
    password_hash: passwordHash,
    profile: {
      company_name: input.company_name,
      company_website: input.company_website
    },
    billing: {
      ...DEFAULT_CUSTOMER_BILLING,
      plan,
      plan_started_at: now
    },
    usage_limits: PLAN_LIMITS[plan],
    status: 'pending_verification',
    created_at: now,
    updated_at: now,
    failed_login_attempts: 0
  };
  
  await dynamoDb.send(new PutCommand({
    TableName: TABLE_NAME,
    Item: {
      PK: `CUSTOMER#${customerId}`,
      SK: `CUSTOMER#${customerId}`,
      ...customer
    },
    ConditionExpression: 'attribute_not_exists(PK)'
  }));
  
  return customer;
}

/**
 * Get customer by ID
 */
export async function getCustomerById(customerId: string): Promise<Customer | null> {
  const result = await dynamoDb.send(new GetCommand({
    TableName: TABLE_NAME,
    Key: {
      PK: `CUSTOMER#${customerId}`,
      SK: `CUSTOMER#${customerId}`
    }
  }));
  
  if (!result.Item) {
    return null;
  }
  
  // Remove DynamoDB keys from response
  const { PK, SK, ...customer } = result.Item;
  return customer as Customer;
}

/**
 * Get customer by email (using GSI)
 */
export async function getCustomerByEmail(email: string): Promise<Customer | null> {
  const result = await dynamoDb.send(new QueryCommand({
    TableName: TABLE_NAME,
    IndexName: EMAIL_INDEX,
    KeyConditionExpression: 'email = :email',
    ExpressionAttributeValues: {
      ':email': email.toLowerCase().trim()
    },
    Limit: 1
  }));
  
  if (!result.Items || result.Items.length === 0) {
    return null;
  }
  
  const { PK, SK, ...customer } = result.Items[0];
  return customer as Customer;
}

/**
 * Update customer
 */
export async function updateCustomer(
  customerId: string, 
  updates: Partial<Omit<Customer, 'id' | 'created_at'>>
): Promise<Customer | null> {
  const updateExpressions: string[] = [];
  const expressionAttributeNames: Record<string, string> = {};
  const expressionAttributeValues: Record<string, unknown> = {};
  
  // Always update updated_at
  updates.updated_at = new Date().toISOString();
  
  Object.entries(updates).forEach(([key, value]) => {
    if (value !== undefined) {
      const attrName = `#${key}`;
      const attrValue = `:${key}`;
      updateExpressions.push(`${attrName} = ${attrValue}`);
      expressionAttributeNames[attrName] = key;
      expressionAttributeValues[attrValue] = value;
    }
  });
  
  if (updateExpressions.length === 0) {
    return getCustomerById(customerId);
  }
  
  const result = await dynamoDb.send(new UpdateCommand({
    TableName: TABLE_NAME,
    Key: {
      PK: `CUSTOMER#${customerId}`,
      SK: `CUSTOMER#${customerId}`
    },
    UpdateExpression: `SET ${updateExpressions.join(', ')}`,
    ExpressionAttributeNames: expressionAttributeNames,
    ExpressionAttributeValues: expressionAttributeValues,
    ReturnValues: 'ALL_NEW'
  }));
  
  if (!result.Attributes) {
    return null;
  }
  
  const { PK, SK, ...customer } = result.Attributes;
  return customer as Customer;
}

/**
 * Update customer plan
 */
export async function updateCustomerPlan(
  customerId: string,
  plan: CustomerPlan,
  stripeSubscriptionId?: string
): Promise<Customer | null> {
  const now = new Date().toISOString();
  
  return updateCustomer(customerId, {
    billing: {
      plan,
      plan_started_at: now,
      stripe_subscription_id: stripeSubscriptionId
    } as Customer['billing'],
    usage_limits: PLAN_LIMITS[plan]
  });
}

/**
 * Record login attempt (success or failure)
 */
export async function recordLoginAttempt(
  customerId: string,
  success: boolean
): Promise<void> {
  const now = new Date().toISOString();
  
  if (success) {
    await dynamoDb.send(new UpdateCommand({
      TableName: TABLE_NAME,
      Key: {
        PK: `CUSTOMER#${customerId}`,
        SK: `CUSTOMER#${customerId}`
      },
      UpdateExpression: 'SET last_login_at = :now, failed_login_attempts = :zero, updated_at = :now',
      ExpressionAttributeValues: {
        ':now': now,
        ':zero': 0
      }
    }));
  } else {
    await dynamoDb.send(new UpdateCommand({
      TableName: TABLE_NAME,
      Key: {
        PK: `CUSTOMER#${customerId}`,
        SK: `CUSTOMER#${customerId}`
      },
      UpdateExpression: 'SET failed_login_attempts = if_not_exists(failed_login_attempts, :zero) + :one, updated_at = :now',
      ExpressionAttributeValues: {
        ':zero': 0,
        ':one': 1,
        ':now': now
      }
    }));
  }
}

/**
 * Lock customer account
 */
export async function lockCustomerAccount(
  customerId: string,
  lockDurationMinutes: number = 30
): Promise<void> {
  const lockedUntil = new Date(Date.now() + lockDurationMinutes * 60 * 1000).toISOString();
  
  await dynamoDb.send(new UpdateCommand({
    TableName: TABLE_NAME,
    Key: {
      PK: `CUSTOMER#${customerId}`,
      SK: `CUSTOMER#${customerId}`
    },
    UpdateExpression: 'SET locked_until = :lockedUntil, updated_at = :now',
    ExpressionAttributeValues: {
      ':lockedUntil': lockedUntil,
      ':now': new Date().toISOString()
    }
  }));
}

/**
 * Verify customer email
 */
export async function verifyCustomerEmail(customerId: string): Promise<Customer | null> {
  return updateCustomer(customerId, {
    email_verified: true,
    status: 'active'
  });
}

/**
 * Set default realm for customer
 */
export async function setDefaultRealm(
  customerId: string,
  realmId: string
): Promise<Customer | null> {
  return updateCustomer(customerId, {
    default_realm_id: realmId
  });
}

/**
 * Delete customer (soft delete - set status to churned)
 */
export async function deleteCustomer(customerId: string): Promise<boolean> {
  const result = await updateCustomer(customerId, {
    status: 'churned'
  });
  return result !== null;
}

/**
 * Check if email exists
 */
export async function emailExists(email: string): Promise<boolean> {
  const customer = await getCustomerByEmail(email);
  return customer !== null;
}

/**
 * Update customer billing information
 */
export async function updateCustomerBilling(
  customerId: string,
  billingUpdates: Partial<Customer['billing']> & Partial<Customer['usage_limits']>
): Promise<Customer | null> {
  const customer = await getCustomerById(customerId);
  if (!customer) {
    return null;
  }

  const updates: Partial<Customer> = {};

  // Separate billing and usage_limits updates
  const billingFields = ['plan', 'stripe_customer_id', 'stripe_subscription_id', 'plan_started_at', 'plan_expires_at', 'payment_method_last4', 'payment_method_brand'];
  const usageLimitFields = ['max_mau', 'max_api_calls', 'max_realms', 'max_api_calls_per_month'];

  const newBilling: Partial<Customer['billing']> = {};
  const newUsageLimits: Partial<Customer['usage_limits']> = {};

  for (const [key, value] of Object.entries(billingUpdates)) {
    if (billingFields.includes(key)) {
      (newBilling as Record<string, unknown>)[key] = value;
    } else if (usageLimitFields.includes(key)) {
      (newUsageLimits as Record<string, unknown>)[key] = value;
    }
  }

  if (Object.keys(newBilling).length > 0) {
    updates.billing = { ...customer.billing, ...newBilling };
  }

  if (Object.keys(newUsageLimits).length > 0) {
    updates.usage_limits = { ...customer.usage_limits, ...newUsageLimits };
  }

  return updateCustomer(customerId, updates);
}

/**
 * Get customer by Stripe customer ID
 */
export async function getCustomerByStripeId(stripeCustomerId: string): Promise<Customer | null> {
  // Note: In production, you'd want a GSI on stripe_customer_id
  // For now, we'll scan (not ideal for large datasets)
  const result = await dynamoDb.send(new QueryCommand({
    TableName: TABLE_NAME,
    IndexName: 'stripe-customer-index', // Assumes GSI exists
    KeyConditionExpression: 'billing.stripe_customer_id = :stripeId',
    ExpressionAttributeValues: {
      ':stripeId': stripeCustomerId
    },
    Limit: 1
  }));

  if (!result.Items || result.Items.length === 0) {
    return null;
  }

  const { PK, SK, ...customer } = result.Items[0];
  return customer as Customer;
}
