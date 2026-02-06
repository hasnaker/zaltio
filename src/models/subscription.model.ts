/**
 * Subscription Model - Tenant Subscription Management for Zalt.io
 * 
 * Subscriptions link tenants to billing plans and track Stripe subscription status.
 * Supports active, past_due, canceled, and trialing statuses.
 * 
 * DynamoDB Schema:
 * - Table: zalt-subscriptions
 * - pk: TENANT#{tenantId}#SUBSCRIPTION#{subscriptionId}
 * - sk: SUBSCRIPTION
 * - GSI: stripe-index (stripeSubscriptionId -> subscriptionId)
 * - GSI: tenant-index (tenantId -> subscriptions)
 * 
 * Security Requirements:
 * - Stripe integration for payment processing
 * - Audit logging for all subscription operations
 * 
 * Validates: Requirements 7.4 (Subscriptions)
 */

import { randomBytes } from 'crypto';

/**
 * Subscription status types
 */
export type SubscriptionStatus = 'active' | 'past_due' | 'canceled' | 'trialing';

/**
 * Subscription entity
 */
export interface Subscription {
  id: string;                           // sub_xxx format
  tenant_id: string;                    // Tenant this subscription belongs to
  plan_id: string;                      // BillingPlan ID
  stripe_subscription_id: string;       // Stripe subscription ID
  stripe_customer_id?: string;          // Stripe customer ID
  status: SubscriptionStatus;           // Current subscription status
  current_period_start: string;         // Current billing period start (ISO 8601)
  current_period_end: string;           // Current billing period end (ISO 8601)
  cancel_at_period_end?: boolean;       // Whether subscription cancels at period end
  canceled_at?: string;                 // When subscription was canceled
  trial_start?: string;                 // Trial period start
  trial_end?: string;                   // Trial period end
  quantity?: number;                    // Number of seats/units (for per_user plans)
  metadata?: SubscriptionMetadata;      // Additional metadata
  created_at: string;                   // Creation timestamp
  updated_at?: string;                  // Last update timestamp
}

/**
 * Subscription metadata for additional context
 */
export interface SubscriptionMetadata {
  created_by?: string;                  // User who created the subscription
  payment_method_id?: string;           // Stripe payment method ID
  coupon_id?: string;                   // Applied coupon ID
  custom_fields?: Record<string, unknown>; // Custom fields for specific use cases
}

/**
 * Input for creating a subscription
 */
export interface CreateSubscriptionInput {
  tenant_id: string;
  plan_id: string;
  stripe_subscription_id: string;
  stripe_customer_id?: string;
  status: SubscriptionStatus;
  current_period_start: string;
  current_period_end: string;
  cancel_at_period_end?: boolean;
  trial_start?: string;
  trial_end?: string;
  quantity?: number;
  metadata?: SubscriptionMetadata;
}

/**
 * Input for updating a subscription
 */
export interface UpdateSubscriptionInput {
  plan_id?: string;
  status?: SubscriptionStatus;
  current_period_start?: string;
  current_period_end?: string;
  cancel_at_period_end?: boolean;
  canceled_at?: string;
  trial_start?: string;
  trial_end?: string;
  quantity?: number;
  metadata?: SubscriptionMetadata;
}

/**
 * Subscription response (API response format)
 */
export interface SubscriptionResponse {
  id: string;
  tenant_id: string;
  plan_id: string;
  stripe_subscription_id: string;
  status: SubscriptionStatus;
  current_period_start: string;
  current_period_end: string;
  cancel_at_period_end?: boolean;
  canceled_at?: string;
  trial_start?: string;
  trial_end?: string;
  quantity?: number;
  created_at: string;
  updated_at?: string;
}

/**
 * Subscription with plan details (for API responses)
 */
export interface SubscriptionWithPlan extends SubscriptionResponse {
  plan_name?: string;
  plan_type?: string;
  features?: string[];
  limits?: Record<string, number>;
}

// ============================================================================
// Constants
// ============================================================================

/**
 * Subscription ID prefix
 */
export const SUBSCRIPTION_ID_PREFIX = 'sub_';

/**
 * Maximum subscriptions per tenant (typically 1, but allows for multiple)
 */
export const MAX_SUBSCRIPTIONS_PER_TENANT = 5;

/**
 * Valid subscription statuses
 */
export const SUBSCRIPTION_STATUSES: SubscriptionStatus[] = [
  'active',
  'past_due',
  'canceled',
  'trialing'
];

/**
 * Stripe subscription ID prefix
 */
export const STRIPE_SUBSCRIPTION_PREFIX = 'sub_';

/**
 * Stripe customer ID prefix
 */
export const STRIPE_CUSTOMER_PREFIX = 'cus_';

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Generate unique subscription ID
 */
export function generateSubscriptionId(): string {
  return `${SUBSCRIPTION_ID_PREFIX}${randomBytes(12).toString('hex')}`;
}

/**
 * Validate subscription status
 */
export function isValidSubscriptionStatus(status: string): status is SubscriptionStatus {
  return SUBSCRIPTION_STATUSES.includes(status as SubscriptionStatus);
}

/**
 * Validate Stripe subscription ID format
 */
export function isValidStripeSubscriptionId(subscriptionId: string): boolean {
  // Stripe subscription IDs start with 'sub_'
  return /^sub_[a-zA-Z0-9]+$/.test(subscriptionId);
}

/**
 * Validate Stripe customer ID format
 */
export function isValidStripeCustomerId(customerId: string): boolean {
  // Stripe customer IDs start with 'cus_'
  return /^cus_[a-zA-Z0-9]+$/.test(customerId);
}

/**
 * Validate ISO 8601 date string
 */
export function isValidISODate(dateString: string): boolean {
  if (typeof dateString !== 'string') return false;
  const date = new Date(dateString);
  return !isNaN(date.getTime()) && dateString.includes('T');
}

/**
 * Validate tenant ID format
 */
export function isValidTenantId(tenantId: string): boolean {
  if (typeof tenantId !== 'string') return false;
  return tenantId.trim().length > 0;
}

/**
 * Validate plan ID format
 */
export function isValidPlanId(planId: string): boolean {
  if (typeof planId !== 'string') return false;
  return /^plan_[a-f0-9]{24}$/.test(planId);
}

/**
 * Validate quantity (for per_user plans)
 */
export function isValidQuantity(quantity: number): boolean {
  return Number.isInteger(quantity) && quantity > 0 && quantity <= 100000;
}

/**
 * Convert Subscription to API response format
 */
export function toSubscriptionResponse(subscription: Subscription): SubscriptionResponse {
  return {
    id: subscription.id,
    tenant_id: subscription.tenant_id,
    plan_id: subscription.plan_id,
    stripe_subscription_id: subscription.stripe_subscription_id,
    status: subscription.status,
    current_period_start: subscription.current_period_start,
    current_period_end: subscription.current_period_end,
    cancel_at_period_end: subscription.cancel_at_period_end,
    canceled_at: subscription.canceled_at,
    trial_start: subscription.trial_start,
    trial_end: subscription.trial_end,
    quantity: subscription.quantity,
    created_at: subscription.created_at,
    updated_at: subscription.updated_at
  };
}

/**
 * Check if subscription is active (includes trialing)
 */
export function isSubscriptionActive(subscription: Subscription): boolean {
  return subscription.status === 'active' || subscription.status === 'trialing';
}

/**
 * Check if subscription is in trial period
 */
export function isInTrialPeriod(subscription: Subscription): boolean {
  if (subscription.status !== 'trialing') return false;
  if (!subscription.trial_end) return false;
  
  const now = new Date();
  const trialEnd = new Date(subscription.trial_end);
  return now < trialEnd;
}

/**
 * Check if subscription is past due
 */
export function isSubscriptionPastDue(subscription: Subscription): boolean {
  return subscription.status === 'past_due';
}

/**
 * Check if subscription is canceled
 */
export function isSubscriptionCanceled(subscription: Subscription): boolean {
  return subscription.status === 'canceled';
}

/**
 * Check if subscription will cancel at period end
 */
export function willCancelAtPeriodEnd(subscription: Subscription): boolean {
  return subscription.cancel_at_period_end === true;
}

/**
 * Get days remaining in current period
 */
export function getDaysRemainingInPeriod(subscription: Subscription): number {
  const now = new Date();
  const periodEnd = new Date(subscription.current_period_end);
  const diffMs = periodEnd.getTime() - now.getTime();
  return Math.max(0, Math.ceil(diffMs / (1000 * 60 * 60 * 24)));
}

/**
 * Get days remaining in trial
 */
export function getDaysRemainingInTrial(subscription: Subscription): number {
  if (!subscription.trial_end) return 0;
  
  const now = new Date();
  const trialEnd = new Date(subscription.trial_end);
  const diffMs = trialEnd.getTime() - now.getTime();
  return Math.max(0, Math.ceil(diffMs / (1000 * 60 * 60 * 24)));
}

/**
 * Check if subscription period has ended
 */
export function hasPeriodEnded(subscription: Subscription): boolean {
  const now = new Date();
  const periodEnd = new Date(subscription.current_period_end);
  return now >= periodEnd;
}

/**
 * Format subscription status for display
 */
export function formatSubscriptionStatus(status: SubscriptionStatus): string {
  const statusMap: Record<SubscriptionStatus, string> = {
    active: 'Active',
    past_due: 'Past Due',
    canceled: 'Canceled',
    trialing: 'Trial'
  };
  return statusMap[status] || status;
}

/**
 * Get subscription status color for UI
 */
export function getSubscriptionStatusColor(status: SubscriptionStatus): string {
  const colorMap: Record<SubscriptionStatus, string> = {
    active: 'green',
    past_due: 'yellow',
    canceled: 'red',
    trialing: 'blue'
  };
  return colorMap[status] || 'gray';
}

/**
 * Compare subscriptions by creation date (newest first)
 */
export function compareSubscriptionsByDate(a: Subscription, b: Subscription): number {
  return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
}

/**
 * Map Stripe subscription status to Zalt status
 */
export function mapStripeStatus(stripeStatus: string): SubscriptionStatus {
  const statusMap: Record<string, SubscriptionStatus> = {
    active: 'active',
    past_due: 'past_due',
    canceled: 'canceled',
    trialing: 'trialing',
    unpaid: 'past_due',
    incomplete: 'past_due',
    incomplete_expired: 'canceled',
    paused: 'canceled'
  };
  return statusMap[stripeStatus] || 'canceled';
}
