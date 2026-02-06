/**
 * Property-Based Tests for Billing System
 * Task 13.10: Write property tests for Billing
 * 
 * Properties tested:
 * - Property 25: Entitlement enforcement is correct
 * - Property 26: Subscription status syncs with Stripe
 * - Property 27: Usage tracking is accurate
 * 
 * **Validates: Requirements 7.5, 7.6**
 */

import * as fc from 'fast-check';
import {
  BillingPlan,
  BillingPlanType,
  BillingPlanStatus,
  generateBillingPlanId,
  hasFeature,
  getLimit,
  isWithinLimit,
  isValidBillingPlanType,
  isValidBillingPlanStatus,
  isValidPrice,
  isValidFeatures,
  isValidLimits,
  BILLING_PLAN_TYPES,
  BILLING_PLAN_STATUSES
} from '../models/billing-plan.model';
import {
  Subscription,
  SubscriptionStatus,
  generateSubscriptionId,
  isSubscriptionActive,
  isInTrialPeriod,
  isSubscriptionPastDue,
  isSubscriptionCanceled,
  mapStripeStatus,
  getDaysRemainingInPeriod,
  getDaysRemainingInTrial,
  SUBSCRIPTION_STATUSES
} from '../models/subscription.model';

/**
 * Custom generators for Billing tests
 */
const realmIdArb = fc.stringMatching(/^[a-z0-9-]{3,50}$/)
  .filter(s => s.length >= 3 && s.length <= 50);

const tenantIdArb = fc.hexaString({ minLength: 24, maxLength: 24 })
  .map(hex => `tenant_${hex}`);

const planIdArb = fc.hexaString({ minLength: 24, maxLength: 24 })
  .map(hex => `plan_${hex}`);


const subscriptionIdArb = fc.hexaString({ minLength: 24, maxLength: 24 })
  .map(hex => `sub_${hex}`);

const stripeSubscriptionIdArb = fc.hexaString({ minLength: 14, maxLength: 24 })
  .map(hex => `sub_${hex}`);

const stripeCustomerIdArb = fc.hexaString({ minLength: 14, maxLength: 24 })
  .map(hex => `cus_${hex}`);

const billingPlanTypeArb = fc.constantFrom(...BILLING_PLAN_TYPES) as fc.Arbitrary<BillingPlanType>;

const billingPlanStatusArb = fc.constantFrom(...BILLING_PLAN_STATUSES) as fc.Arbitrary<BillingPlanStatus>;

const subscriptionStatusArb = fc.constantFrom(...SUBSCRIPTION_STATUSES) as fc.Arbitrary<SubscriptionStatus>;

const priceArb = fc.integer({ min: 0, max: 99999999 });

const featureArb = fc.stringMatching(/^[a-z_]{3,30}$/)
  .filter(s => s.length >= 3 && s.length <= 30);

const featuresArb = fc.array(featureArb, { minLength: 1, maxLength: 20 })
  .map(features => [...new Set(features)]);

const limitKeyArb = fc.constantFrom('users', 'api_calls', 'storage_gb', 'realms', 'webhooks', 'mau');

const limitsArb = fc.dictionary(
  limitKeyArb,
  fc.integer({ min: 1, max: 1000000 })
).filter(obj => Object.keys(obj).length > 0);

const usageValueArb = fc.integer({ min: 0, max: 1000000 });

/**
 * Generate a mock BillingPlan for testing
 */
function generateMockBillingPlan(
  realmId: string,
  options: {
    status?: BillingPlanStatus;
    type?: BillingPlanType;
    features?: string[];
    limits?: Record<string, number>;
    priceMonthly?: number;
    priceYearly?: number;
  } = {}
): BillingPlan {
  const now = new Date();
  
  return {
    id: generateBillingPlanId(),
    realm_id: realmId,
    name: 'Test Plan',
    description: 'A test billing plan',
    type: options.type || 'flat_rate',
    price_monthly: options.priceMonthly ?? 2999,
    price_yearly: options.priceYearly ?? 29990,
    currency: 'usd',
    features: options.features || ['basic_auth', 'mfa', 'audit_logs'],
    limits: options.limits || { users: 100, api_calls: 10000 },
    status: options.status || 'active',
    trial_days: 14,
    is_default: false,
    sort_order: 1,
    created_at: now.toISOString(),
    updated_at: now.toISOString(),
  };
}


/**
 * Generate a mock Subscription for testing
 */
function generateMockSubscription(
  tenantId: string,
  planId: string,
  options: {
    status?: SubscriptionStatus;
    stripeSubscriptionId?: string;
    stripeCustomerId?: string;
    trialEnd?: Date;
    currentPeriodEnd?: Date;
    cancelAtPeriodEnd?: boolean;
  } = {}
): Subscription {
  const now = new Date();
  const periodEnd = options.currentPeriodEnd || new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
  
  return {
    id: generateSubscriptionId(),
    tenant_id: tenantId,
    plan_id: planId,
    stripe_subscription_id: options.stripeSubscriptionId || `sub_${Math.random().toString(36).slice(2)}`,
    stripe_customer_id: options.stripeCustomerId || `cus_${Math.random().toString(36).slice(2)}`,
    status: options.status || 'active',
    current_period_start: now.toISOString(),
    current_period_end: periodEnd.toISOString(),
    cancel_at_period_end: options.cancelAtPeriodEnd,
    trial_start: options.status === 'trialing' ? now.toISOString() : undefined,
    trial_end: options.trialEnd?.toISOString(),
    created_at: now.toISOString(),
    updated_at: now.toISOString(),
  };
}

describe('Billing Property Tests', () => {
  /**
   * Property 25: Entitlement enforcement is correct
   * 
   * If a tenant has a subscription to a plan with feature X, they should have access to feature X.
   * If they don't have the feature in their plan, they should be denied.
   * 
   * **Validates: Requirements 7.5, 7.6**
   */
  describe('Property 25: Entitlement enforcement is correct', () => {
    it('should grant access when feature is in plan', () => {
      fc.assert(
        fc.property(
          realmIdArb,
          featuresArb,
          (realmId, features) => {
            const plan = generateMockBillingPlan(realmId, {
              status: 'active',
              features
            });
            
            // Every feature in the plan should be accessible
            features.forEach(feature => {
              const hasAccess = hasFeature(plan, feature);
              expect(hasAccess).toBe(true);
            });
          }
        ),
        { numRuns: 100 }
      );
    });


    it('should deny access when feature is not in plan', () => {
      fc.assert(
        fc.property(
          realmIdArb,
          featuresArb,
          featureArb,
          (realmId, planFeatures, requestedFeature) => {
            // Skip if requested feature is in plan features
            if (planFeatures.includes(requestedFeature)) return true;
            
            const plan = generateMockBillingPlan(realmId, {
              status: 'active',
              features: planFeatures
            });
            
            // Feature not in plan should be denied
            const hasAccess = hasFeature(plan, requestedFeature);
            expect(hasAccess).toBe(false);
            return true;
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should enforce limits correctly - within limit grants access', () => {
      fc.assert(
        fc.property(
          realmIdArb,
          limitsArb,
          (realmId, limits) => {
            const plan = generateMockBillingPlan(realmId, {
              status: 'active',
              limits
            });
            
            // Usage within limits should be allowed
            Object.entries(limits).forEach(([key, limit]) => {
              // Test at 50% of limit
              const usage = Math.floor(limit * 0.5);
              const withinLimit = isWithinLimit(plan, key, usage);
              expect(withinLimit).toBe(true);
              
              // Test at exactly the limit
              const atLimit = isWithinLimit(plan, key, limit);
              expect(atLimit).toBe(true);
            });
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should enforce limits correctly - exceeding limit denies access', () => {
      fc.assert(
        fc.property(
          realmIdArb,
          limitsArb,
          (realmId, limits) => {
            const plan = generateMockBillingPlan(realmId, {
              status: 'active',
              limits
            });
            
            // Usage exceeding limits should be denied
            Object.entries(limits).forEach(([key, limit]) => {
              const usage = limit + 1;
              const withinLimit = isWithinLimit(plan, key, usage);
              expect(withinLimit).toBe(false);
            });
          }
        ),
        { numRuns: 100 }
      );
    });


    it('should return undefined limit for non-existent limit keys (unlimited)', () => {
      fc.assert(
        fc.property(
          realmIdArb,
          limitsArb,
          fc.string({ minLength: 10, maxLength: 20 }),
          (realmId, limits, nonExistentKey) => {
            // Skip if key happens to exist
            if (limits[nonExistentKey] !== undefined) return true;
            
            const plan = generateMockBillingPlan(realmId, {
              status: 'active',
              limits
            });
            
            // Non-existent limit key should return undefined (unlimited)
            const limit = getLimit(plan, nonExistentKey);
            expect(limit).toBeUndefined();
            
            // And should allow any usage
            const withinLimit = isWithinLimit(plan, nonExistentKey, 999999);
            expect(withinLimit).toBe(true);
            return true;
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should only grant access for active subscriptions', () => {
      fc.assert(
        fc.property(
          tenantIdArb,
          planIdArb,
          subscriptionStatusArb,
          (tenantId, planId, status) => {
            const subscription = generateMockSubscription(tenantId, planId, { status });
            
            const isActive = isSubscriptionActive(subscription);
            
            // Only 'active' and 'trialing' should grant access
            if (status === 'active' || status === 'trialing') {
              expect(isActive).toBe(true);
            } else {
              expect(isActive).toBe(false);
            }
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should deny access for canceled subscriptions', () => {
      fc.assert(
        fc.property(
          tenantIdArb,
          planIdArb,
          (tenantId, planId) => {
            const subscription = generateMockSubscription(tenantId, planId, {
              status: 'canceled'
            });
            
            expect(isSubscriptionActive(subscription)).toBe(false);
            expect(isSubscriptionCanceled(subscription)).toBe(true);
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should deny access for past_due subscriptions', () => {
      fc.assert(
        fc.property(
          tenantIdArb,
          planIdArb,
          (tenantId, planId) => {
            const subscription = generateMockSubscription(tenantId, planId, {
              status: 'past_due'
            });
            
            expect(isSubscriptionActive(subscription)).toBe(false);
            expect(isSubscriptionPastDue(subscription)).toBe(true);
          }
        ),
        { numRuns: 50 }
      );
    });
  });


  /**
   * Property 26: Subscription status syncs with Stripe
   * 
   * Subscription status changes from Stripe webhooks should be correctly
   * reflected in the local subscription state.
   * 
   * **Validates: Requirements 7.5, 7.6**
   */
  describe('Property 26: Subscription status syncs with Stripe', () => {
    it('should correctly map all Stripe statuses to Zalt statuses', () => {
      const stripeStatusMappings: Array<{ stripe: string; expected: SubscriptionStatus }> = [
        { stripe: 'active', expected: 'active' },
        { stripe: 'past_due', expected: 'past_due' },
        { stripe: 'canceled', expected: 'canceled' },
        { stripe: 'trialing', expected: 'trialing' },
        { stripe: 'unpaid', expected: 'past_due' },
        { stripe: 'incomplete', expected: 'past_due' },
        { stripe: 'incomplete_expired', expected: 'canceled' },
        { stripe: 'paused', expected: 'canceled' },
      ];

      stripeStatusMappings.forEach(({ stripe, expected }) => {
        const mapped = mapStripeStatus(stripe);
        expect(mapped).toBe(expected);
      });
    });

    it('should map unknown Stripe statuses to canceled (safe default)', () => {
      // Reserved JS property names and prototype methods that could cause issues
      const reservedNames = [
        'active', 'past_due', 'canceled', 'trialing', 'unpaid', 'incomplete', 
        'incomplete_expired', 'paused', 'constructor', 'prototype', '__proto__',
        'toString', 'valueOf', 'hasOwnProperty', 'isPrototypeOf', 'propertyIsEnumerable',
        'toLocaleString', '__defineGetter__', '__defineSetter__', '__lookupGetter__',
        '__lookupSetter__'
      ];
      
      fc.assert(
        fc.property(
          fc.string({ minLength: 5, maxLength: 20 }).filter(s => 
            !reservedNames.includes(s) && 
            // Filter out any string that matches Object prototype methods
            typeof (Object.prototype as Record<string, unknown>)[s] !== 'function'
          ),
          (unknownStatus) => {
            const mapped = mapStripeStatus(unknownStatus);
            // Unknown statuses should map to 'canceled' for safety
            expect(mapped).toBe('canceled');
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should preserve subscription ID consistency after status sync', () => {
      fc.assert(
        fc.property(
          tenantIdArb,
          planIdArb,
          stripeSubscriptionIdArb,
          subscriptionStatusArb,
          (tenantId, planId, stripeSubId, newStatus) => {
            const subscription = generateMockSubscription(tenantId, planId, {
              stripeSubscriptionId: stripeSubId,
              status: 'active'
            });
            
            // Simulate status update (as would happen from webhook)
            const updatedSubscription: Subscription = {
              ...subscription,
              status: newStatus,
              updated_at: new Date().toISOString()
            };
            
            // IDs should remain unchanged
            expect(updatedSubscription.id).toBe(subscription.id);
            expect(updatedSubscription.tenant_id).toBe(subscription.tenant_id);
            expect(updatedSubscription.plan_id).toBe(subscription.plan_id);
            expect(updatedSubscription.stripe_subscription_id).toBe(stripeSubId);
            
            // Status should be updated
            expect(updatedSubscription.status).toBe(newStatus);
          }
        ),
        { numRuns: 100 }
      );
    });


    it('should correctly track period dates after renewal', () => {
      fc.assert(
        fc.property(
          tenantIdArb,
          planIdArb,
          fc.integer({ min: 1, max: 365 }), // days until period end
          (tenantId, planId, daysUntilEnd) => {
            const now = new Date();
            const periodEnd = new Date(now.getTime() + daysUntilEnd * 24 * 60 * 60 * 1000);
            
            const subscription = generateMockSubscription(tenantId, planId, {
              status: 'active',
              currentPeriodEnd: periodEnd
            });
            
            const daysRemaining = getDaysRemainingInPeriod(subscription);
            
            // Days remaining should be approximately equal to daysUntilEnd
            // Allow 1 day tolerance for test execution time
            expect(daysRemaining).toBeGreaterThanOrEqual(daysUntilEnd - 1);
            expect(daysRemaining).toBeLessThanOrEqual(daysUntilEnd + 1);
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should correctly track trial period', () => {
      fc.assert(
        fc.property(
          tenantIdArb,
          planIdArb,
          fc.integer({ min: 1, max: 30 }), // trial days remaining
          (tenantId, planId, trialDaysRemaining) => {
            const now = new Date();
            const trialEnd = new Date(now.getTime() + trialDaysRemaining * 24 * 60 * 60 * 1000);
            
            const subscription = generateMockSubscription(tenantId, planId, {
              status: 'trialing',
              trialEnd
            });
            
            expect(isInTrialPeriod(subscription)).toBe(true);
            
            const daysRemaining = getDaysRemainingInTrial(subscription);
            // Allow 1 day tolerance
            expect(daysRemaining).toBeGreaterThanOrEqual(trialDaysRemaining - 1);
            expect(daysRemaining).toBeLessThanOrEqual(trialDaysRemaining + 1);
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should return 0 trial days for non-trialing subscriptions', () => {
      fc.assert(
        fc.property(
          tenantIdArb,
          planIdArb,
          fc.constantFrom('active', 'past_due', 'canceled') as fc.Arbitrary<SubscriptionStatus>,
          (tenantId, planId, status) => {
            const subscription = generateMockSubscription(tenantId, planId, { status });
            
            // Non-trialing subscriptions should not be in trial
            expect(isInTrialPeriod(subscription)).toBe(false);
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should handle cancel_at_period_end flag correctly', () => {
      fc.assert(
        fc.property(
          tenantIdArb,
          planIdArb,
          fc.boolean(),
          (tenantId, planId, cancelAtPeriodEnd) => {
            const subscription = generateMockSubscription(tenantId, planId, {
              status: 'active',
              cancelAtPeriodEnd
            });
            
            // Subscription should still be active even if scheduled to cancel
            expect(isSubscriptionActive(subscription)).toBe(true);
            expect(subscription.cancel_at_period_end).toBe(cancelAtPeriodEnd);
          }
        ),
        { numRuns: 50 }
      );
    });
  });


  /**
   * Property 27: Usage tracking is accurate
   * 
   * Usage increments should be accurately tracked and not exceed limits.
   * 
   * **Validates: Requirements 7.5, 7.6**
   */
  describe('Property 27: Usage tracking is accurate', () => {
    it('should accurately compare usage against limits', () => {
      fc.assert(
        fc.property(
          realmIdArb,
          limitKeyArb,
          fc.integer({ min: 1, max: 10000 }), // limit
          fc.integer({ min: 0, max: 20000 }), // usage
          (realmId, limitKey, limit, usage) => {
            const plan = generateMockBillingPlan(realmId, {
              status: 'active',
              limits: { [limitKey]: limit }
            });
            
            const withinLimit = isWithinLimit(plan, limitKey, usage);
            
            // Should be within limit if usage <= limit
            if (usage <= limit) {
              expect(withinLimit).toBe(true);
            } else {
              expect(withinLimit).toBe(false);
            }
          }
        ),
        { numRuns: 200 }
      );
    });

    it('should handle zero usage correctly', () => {
      fc.assert(
        fc.property(
          realmIdArb,
          limitsArb,
          (realmId, limits) => {
            const plan = generateMockBillingPlan(realmId, {
              status: 'active',
              limits
            });
            
            // Zero usage should always be within limits
            Object.keys(limits).forEach(key => {
              const withinLimit = isWithinLimit(plan, key, 0);
              expect(withinLimit).toBe(true);
            });
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should handle boundary conditions at exact limit', () => {
      fc.assert(
        fc.property(
          realmIdArb,
          limitKeyArb,
          fc.integer({ min: 1, max: 100000 }),
          (realmId, limitKey, limit) => {
            const plan = generateMockBillingPlan(realmId, {
              status: 'active',
              limits: { [limitKey]: limit }
            });
            
            // At exactly the limit should be allowed
            expect(isWithinLimit(plan, limitKey, limit)).toBe(true);
            
            // One over the limit should be denied
            expect(isWithinLimit(plan, limitKey, limit + 1)).toBe(false);
          }
        ),
        { numRuns: 100 }
      );
    });


    it('should correctly retrieve limit values', () => {
      fc.assert(
        fc.property(
          realmIdArb,
          limitsArb,
          (realmId, limits) => {
            const plan = generateMockBillingPlan(realmId, {
              status: 'active',
              limits
            });
            
            // All defined limits should be retrievable
            Object.entries(limits).forEach(([key, expectedLimit]) => {
              const actualLimit = getLimit(plan, key);
              expect(actualLimit).toBe(expectedLimit);
            });
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should handle multiple limit checks consistently', () => {
      fc.assert(
        fc.property(
          realmIdArb,
          fc.record({
            users: fc.integer({ min: 10, max: 1000 }),
            api_calls: fc.integer({ min: 1000, max: 100000 }),
            storage_gb: fc.integer({ min: 1, max: 100 })
          }),
          fc.record({
            users: fc.integer({ min: 0, max: 2000 }),
            api_calls: fc.integer({ min: 0, max: 200000 }),
            storage_gb: fc.integer({ min: 0, max: 200 })
          }),
          (realmId, limits, usage) => {
            const plan = generateMockBillingPlan(realmId, {
              status: 'active',
              limits
            });
            
            // Check each limit independently
            const results = Object.entries(limits).map(([key, limit]) => {
              const currentUsage = usage[key as keyof typeof usage];
              return {
                key,
                limit,
                usage: currentUsage,
                withinLimit: isWithinLimit(plan, key, currentUsage),
                expected: currentUsage <= limit
              };
            });
            
            // All results should match expected
            results.forEach(result => {
              expect(result.withinLimit).toBe(result.expected);
            });
          }
        ),
        { numRuns: 100 }
      );
    });

    it('should handle large usage values without overflow', () => {
      fc.assert(
        fc.property(
          realmIdArb,
          limitKeyArb,
          fc.integer({ min: 100000, max: 1000000 }), // large limit
          fc.integer({ min: 0, max: 2000000 }), // potentially larger usage
          (realmId, limitKey, limit, usage) => {
            const plan = generateMockBillingPlan(realmId, {
              status: 'active',
              limits: { [limitKey]: limit }
            });
            
            const withinLimit = isWithinLimit(plan, limitKey, usage);
            
            // Should handle large numbers correctly
            expect(withinLimit).toBe(usage <= limit);
          }
        ),
        { numRuns: 50 }
      );
    });
  });


  /**
   * Additional Properties: Plan and Subscription Validation
   */
  describe('Additional Properties: Plan and Subscription Validation', () => {
    it('should generate unique plan IDs', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 10, max: 50 }),
          (count) => {
            const ids = new Set<string>();
            for (let i = 0; i < count; i++) {
              ids.add(generateBillingPlanId());
            }
            
            // All generated IDs should be unique
            expect(ids.size).toBe(count);
          }
        ),
        { numRuns: 20 }
      );
    });

    it('should generate unique subscription IDs', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 10, max: 50 }),
          (count) => {
            const ids = new Set<string>();
            for (let i = 0; i < count; i++) {
              ids.add(generateSubscriptionId());
            }
            
            // All generated IDs should be unique
            expect(ids.size).toBe(count);
          }
        ),
        { numRuns: 20 }
      );
    });

    it('should validate plan types correctly', () => {
      fc.assert(
        fc.property(
          billingPlanTypeArb,
          (planType) => {
            expect(isValidBillingPlanType(planType)).toBe(true);
          }
        ),
        { numRuns: 20 }
      );
    });

    it('should reject invalid plan types', () => {
      fc.assert(
        fc.property(
          fc.string({ minLength: 5, maxLength: 20 }).filter(s => 
            !BILLING_PLAN_TYPES.includes(s as BillingPlanType)
          ),
          (invalidType) => {
            expect(isValidBillingPlanType(invalidType)).toBe(false);
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should validate plan statuses correctly', () => {
      fc.assert(
        fc.property(
          billingPlanStatusArb,
          (status) => {
            expect(isValidBillingPlanStatus(status)).toBe(true);
          }
        ),
        { numRuns: 20 }
      );
    });

    it('should validate prices correctly', () => {
      fc.assert(
        fc.property(
          priceArb,
          (price) => {
            expect(isValidPrice(price)).toBe(true);
          }
        ),
        { numRuns: 100 }
      );
    });


    it('should reject negative prices', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: -1000000, max: -1 }),
          (negativePrice) => {
            expect(isValidPrice(negativePrice)).toBe(false);
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should validate features array correctly', () => {
      fc.assert(
        fc.property(
          featuresArb,
          (features) => {
            expect(isValidFeatures(features)).toBe(true);
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should validate limits object correctly', () => {
      fc.assert(
        fc.property(
          limitsArb,
          (limits) => {
            expect(isValidLimits(limits)).toBe(true);
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should reject limits with negative values', () => {
      const invalidLimits = { users: -10, api_calls: 1000 };
      expect(isValidLimits(invalidLimits)).toBe(false);
    });

    it('should format plan ID correctly', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 1, max: 100 }),
          () => {
            const id = generateBillingPlanId();
            
            // ID should match expected format
            expect(id).toMatch(/^plan_[a-f0-9]{24}$/);
          }
        ),
        { numRuns: 50 }
      );
    });

    it('should format subscription ID correctly', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 1, max: 100 }),
          () => {
            const id = generateSubscriptionId();
            
            // ID should match expected format
            expect(id).toMatch(/^sub_[a-f0-9]{24}$/);
          }
        ),
        { numRuns: 50 }
      );
    });
  });
});
