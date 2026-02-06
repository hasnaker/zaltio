/**
 * BillingPlan Model - Billing Plan Configuration for Zalt.io
 * 
 * Billing plans define subscription tiers with features, limits, and pricing.
 * Supports per-user, per-organization, flat-rate, and usage-based billing.
 * 
 * DynamoDB Schema:
 * - Table: zalt-billing-plans
 * - pk: REALM#{realmId}#PLAN#{planId}
 * - sk: PLAN
 * - GSI: realm-index (realmId -> plans)
 * 
 * Security Requirements:
 * - Stripe integration for payment processing
 * - Audit logging for all billing operations
 * 
 * Validates: Requirements 7.2 (Billing Plans)
 */

import { randomBytes } from 'crypto';

/**
 * Billing plan types
 */
export type BillingPlanType = 'per_user' | 'per_org' | 'flat_rate' | 'usage_based';

/**
 * Billing plan status
 */
export type BillingPlanStatus = 'active' | 'inactive' | 'archived';

/**
 * Billing interval
 */
export type BillingInterval = 'monthly' | 'yearly';

/**
 * BillingPlan entity
 */
export interface BillingPlan {
  id: string;                           // plan_xxx format
  realm_id: string;                     // Realm this plan belongs to
  name: string;                         // Plan display name (e.g., "Pro", "Enterprise")
  description?: string;                 // Optional plan description
  type: BillingPlanType;                // Billing model type
  price_monthly: number;                // Monthly price in cents
  price_yearly: number;                 // Yearly price in cents
  currency: string;                     // Currency code (e.g., "usd", "eur")
  features: string[];                   // List of included features
  limits: Record<string, number>;       // Usage limits (e.g., { users: 10, storage_gb: 100 })
  stripe_price_id_monthly?: string;     // Stripe price ID for monthly billing
  stripe_price_id_yearly?: string;      // Stripe price ID for yearly billing
  stripe_product_id?: string;           // Stripe product ID
  status: BillingPlanStatus;            // Current status
  trial_days?: number;                  // Trial period in days
  is_default?: boolean;                 // Default plan for new tenants
  sort_order?: number;                  // Display order in pricing table
  metadata?: BillingPlanMetadata;       // Additional metadata
  created_at: string;                   // Creation timestamp
  updated_at?: string;                  // Last update timestamp
}

/**
 * BillingPlan metadata for additional context
 */
export interface BillingPlanMetadata {
  created_by?: string;                  // User who created the plan
  highlight_text?: string;              // Badge text (e.g., "Most Popular")
  custom_fields?: Record<string, unknown>; // Custom fields for specific use cases
}

/**
 * Input for creating a billing plan
 */
export interface CreateBillingPlanInput {
  realm_id: string;
  name: string;
  description?: string;
  type: BillingPlanType;
  price_monthly: number;
  price_yearly: number;
  currency?: string;
  features: string[];
  limits: Record<string, number>;
  stripe_price_id_monthly?: string;
  stripe_price_id_yearly?: string;
  stripe_product_id?: string;
  trial_days?: number;
  is_default?: boolean;
  sort_order?: number;
  metadata?: BillingPlanMetadata;
}

/**
 * Input for updating a billing plan
 */
export interface UpdateBillingPlanInput {
  name?: string;
  description?: string;
  type?: BillingPlanType;
  price_monthly?: number;
  price_yearly?: number;
  currency?: string;
  features?: string[];
  limits?: Record<string, number>;
  stripe_price_id_monthly?: string;
  stripe_price_id_yearly?: string;
  stripe_product_id?: string;
  status?: BillingPlanStatus;
  trial_days?: number;
  is_default?: boolean;
  sort_order?: number;
  metadata?: BillingPlanMetadata;
}

/**
 * BillingPlan response (API response format)
 */
export interface BillingPlanResponse {
  id: string;
  realm_id: string;
  name: string;
  description?: string;
  type: BillingPlanType;
  price_monthly: number;
  price_yearly: number;
  currency: string;
  features: string[];
  limits: Record<string, number>;
  stripe_price_id_monthly?: string;
  stripe_price_id_yearly?: string;
  status: BillingPlanStatus;
  trial_days?: number;
  is_default?: boolean;
  sort_order?: number;
  highlight_text?: string;
  created_at: string;
  updated_at?: string;
}

/**
 * Plan comparison for pricing table
 */
export interface PlanComparison {
  plans: BillingPlanResponse[];
  feature_matrix: FeatureMatrixRow[];
}

/**
 * Feature matrix row for plan comparison
 */
export interface FeatureMatrixRow {
  feature: string;
  description?: string;
  values: Record<string, boolean | number | string>;
}

// ============================================================================
// Constants
// ============================================================================

/**
 * BillingPlan ID prefix
 */
export const BILLING_PLAN_ID_PREFIX = 'plan_';

/**
 * Maximum plans per realm
 */
export const MAX_PLANS_PER_REALM = 20;

/**
 * Maximum features per plan
 */
export const MAX_FEATURES_PER_PLAN = 50;

/**
 * Maximum limits per plan
 */
export const MAX_LIMITS_PER_PLAN = 30;

/**
 * Default currency
 */
export const DEFAULT_CURRENCY = 'usd';

/**
 * Valid billing plan types
 */
export const BILLING_PLAN_TYPES: BillingPlanType[] = [
  'per_user',
  'per_org',
  'flat_rate',
  'usage_based'
];

/**
 * Valid billing plan statuses
 */
export const BILLING_PLAN_STATUSES: BillingPlanStatus[] = [
  'active',
  'inactive',
  'archived'
];

/**
 * Minimum price (0 = free tier)
 */
export const MIN_PRICE = 0;

/**
 * Maximum price (in cents) - $999,999.99
 */
export const MAX_PRICE = 99999999;

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Generate unique billing plan ID
 */
export function generateBillingPlanId(): string {
  return `${BILLING_PLAN_ID_PREFIX}${randomBytes(12).toString('hex')}`;
}

/**
 * Validate billing plan type
 */
export function isValidBillingPlanType(type: string): type is BillingPlanType {
  return BILLING_PLAN_TYPES.includes(type as BillingPlanType);
}

/**
 * Validate billing plan status
 */
export function isValidBillingPlanStatus(status: string): status is BillingPlanStatus {
  return BILLING_PLAN_STATUSES.includes(status as BillingPlanStatus);
}

/**
 * Validate price value
 */
export function isValidPrice(price: number): boolean {
  return Number.isInteger(price) && price >= MIN_PRICE && price <= MAX_PRICE;
}

/**
 * Validate currency code (ISO 4217)
 */
export function isValidCurrency(currency: string): boolean {
  // Common currency codes supported by Stripe
  const validCurrencies = [
    'usd', 'eur', 'gbp', 'jpy', 'cad', 'aud', 'chf', 'cny', 'inr', 'brl',
    'mxn', 'sgd', 'hkd', 'nzd', 'sek', 'nok', 'dkk', 'pln', 'try', 'krw'
  ];
  return validCurrencies.includes(currency.toLowerCase());
}

/**
 * Validate features array
 */
export function isValidFeatures(features: string[]): boolean {
  if (!Array.isArray(features)) return false;
  if (features.length > MAX_FEATURES_PER_PLAN) return false;
  return features.every(f => typeof f === 'string' && f.trim().length > 0);
}

/**
 * Validate limits object
 */
export function isValidLimits(limits: Record<string, number>): boolean {
  if (typeof limits !== 'object' || limits === null || Array.isArray(limits)) return false;
  const keys = Object.keys(limits);
  if (keys.length > MAX_LIMITS_PER_PLAN) return false;
  return keys.every(key => {
    const value = limits[key];
    return typeof key === 'string' && 
           key.trim().length > 0 && 
           typeof value === 'number' && 
           Number.isInteger(value) && 
           value >= 0;
  });
}

/**
 * Validate plan name
 */
export function isValidPlanName(name: string): boolean {
  if (typeof name !== 'string') return false;
  const trimmed = name.trim();
  return trimmed.length >= 1 && trimmed.length <= 100;
}

/**
 * Validate Stripe price ID format
 */
export function isValidStripePriceId(priceId: string): boolean {
  // Stripe price IDs start with 'price_'
  return /^price_[a-zA-Z0-9]+$/.test(priceId);
}

/**
 * Validate Stripe product ID format
 */
export function isValidStripeProductId(productId: string): boolean {
  // Stripe product IDs start with 'prod_'
  return /^prod_[a-zA-Z0-9]+$/.test(productId);
}

/**
 * Convert BillingPlan to API response format
 */
export function toBillingPlanResponse(plan: BillingPlan): BillingPlanResponse {
  return {
    id: plan.id,
    realm_id: plan.realm_id,
    name: plan.name,
    description: plan.description,
    type: plan.type,
    price_monthly: plan.price_monthly,
    price_yearly: plan.price_yearly,
    currency: plan.currency,
    features: plan.features,
    limits: plan.limits,
    stripe_price_id_monthly: plan.stripe_price_id_monthly,
    stripe_price_id_yearly: plan.stripe_price_id_yearly,
    status: plan.status,
    trial_days: plan.trial_days,
    is_default: plan.is_default,
    sort_order: plan.sort_order,
    highlight_text: plan.metadata?.highlight_text,
    created_at: plan.created_at,
    updated_at: plan.updated_at
  };
}

/**
 * Calculate yearly savings percentage
 */
export function calculateYearlySavings(priceMonthly: number, priceYearly: number): number {
  if (priceMonthly <= 0) return 0;
  const monthlyTotal = priceMonthly * 12;
  if (monthlyTotal <= priceYearly) return 0;
  return Math.round(((monthlyTotal - priceYearly) / monthlyTotal) * 100);
}

/**
 * Format price for display
 */
export function formatPrice(priceInCents: number, currency: string): string {
  const amount = priceInCents / 100;
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: currency.toUpperCase()
  }).format(amount);
}

/**
 * Check if a feature is included in a plan
 */
export function hasFeature(plan: BillingPlan, feature: string): boolean {
  return plan.features.includes(feature);
}

/**
 * Get limit value for a plan
 */
export function getLimit(plan: BillingPlan, limitKey: string): number | undefined {
  return plan.limits[limitKey];
}

/**
 * Check if usage is within plan limits
 */
export function isWithinLimit(plan: BillingPlan, limitKey: string, currentUsage: number): boolean {
  const limit = plan.limits[limitKey];
  if (limit === undefined) return true; // No limit defined = unlimited
  return currentUsage <= limit;
}

/**
 * Compare two plans by sort order
 */
export function comparePlansBySortOrder(a: BillingPlan, b: BillingPlan): number {
  const orderA = a.sort_order ?? Number.MAX_SAFE_INTEGER;
  const orderB = b.sort_order ?? Number.MAX_SAFE_INTEGER;
  return orderA - orderB;
}

/**
 * Get the best plan for a given feature requirement
 */
export function findPlanWithFeature(plans: BillingPlan[], feature: string): BillingPlan | undefined {
  return plans
    .filter(p => p.status === 'active' && hasFeature(p, feature))
    .sort(comparePlansBySortOrder)[0];
}

/**
 * Get the cheapest plan that meets limit requirements
 */
export function findCheapestPlanForLimits(
  plans: BillingPlan[],
  requirements: Record<string, number>,
  interval: BillingInterval = 'monthly'
): BillingPlan | undefined {
  return plans
    .filter(p => {
      if (p.status !== 'active') return false;
      return Object.entries(requirements).every(([key, required]) => {
        const limit = p.limits[key];
        return limit === undefined || limit >= required;
      });
    })
    .sort((a, b) => {
      const priceA = interval === 'monthly' ? a.price_monthly : a.price_yearly;
      const priceB = interval === 'monthly' ? b.price_monthly : b.price_yearly;
      return priceA - priceB;
    })[0];
}
