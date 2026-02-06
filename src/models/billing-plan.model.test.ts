/**
 * BillingPlan Model Tests
 * Tests for billing plan model utilities and helper functions
 * 
 * Validates: Requirements 7.2 (Billing Plans)
 * ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
 */

import {
  generateBillingPlanId,
  isValidBillingPlanType,
  isValidBillingPlanStatus,
  isValidPrice,
  isValidCurrency,
  isValidFeatures,
  isValidLimits,
  isValidPlanName,
  isValidStripePriceId,
  isValidStripeProductId,
  toBillingPlanResponse,
  calculateYearlySavings,
  formatPrice,
  hasFeature,
  getLimit,
  isWithinLimit,
  comparePlansBySortOrder,
  findPlanWithFeature,
  findCheapestPlanForLimits,
  BILLING_PLAN_ID_PREFIX,
  BILLING_PLAN_TYPES,
  BILLING_PLAN_STATUSES,
  MAX_FEATURES_PER_PLAN,
  MAX_LIMITS_PER_PLAN,
  MIN_PRICE,
  MAX_PRICE,
  BillingPlan,
  BillingPlanType
} from './billing-plan.model';

describe('BillingPlan Model Utilities', () => {
  describe('generateBillingPlanId', () => {
    it('should generate ID with plan_ prefix', () => {
      const id = generateBillingPlanId();
      expect(id).toMatch(/^plan_[a-f0-9]{24}$/);
      expect(id.startsWith(BILLING_PLAN_ID_PREFIX)).toBe(true);
    });
    
    it('should generate unique IDs', () => {
      const ids = new Set<string>();
      for (let i = 0; i < 100; i++) {
        ids.add(generateBillingPlanId());
      }
      expect(ids.size).toBe(100);
    });
  });
  
  describe('isValidBillingPlanType', () => {
    it('should accept valid plan types', () => {
      expect(isValidBillingPlanType('per_user')).toBe(true);
      expect(isValidBillingPlanType('per_org')).toBe(true);
      expect(isValidBillingPlanType('flat_rate')).toBe(true);
      expect(isValidBillingPlanType('usage_based')).toBe(true);
    });
    
    it('should reject invalid plan types', () => {
      expect(isValidBillingPlanType('invalid')).toBe(false);
      expect(isValidBillingPlanType('PER_USER')).toBe(false);
      expect(isValidBillingPlanType('')).toBe(false);
      expect(isValidBillingPlanType('monthly')).toBe(false);
    });
    
    it('should validate all defined types', () => {
      for (const type of BILLING_PLAN_TYPES) {
        expect(isValidBillingPlanType(type)).toBe(true);
      }
    });
  });
  
  describe('isValidBillingPlanStatus', () => {
    it('should accept valid statuses', () => {
      expect(isValidBillingPlanStatus('active')).toBe(true);
      expect(isValidBillingPlanStatus('inactive')).toBe(true);
      expect(isValidBillingPlanStatus('archived')).toBe(true);
    });
    
    it('should reject invalid statuses', () => {
      expect(isValidBillingPlanStatus('invalid')).toBe(false);
      expect(isValidBillingPlanStatus('ACTIVE')).toBe(false);
      expect(isValidBillingPlanStatus('')).toBe(false);
      expect(isValidBillingPlanStatus('deleted')).toBe(false);
    });
    
    it('should validate all defined statuses', () => {
      for (const status of BILLING_PLAN_STATUSES) {
        expect(isValidBillingPlanStatus(status)).toBe(true);
      }
    });
  });
  
  describe('isValidPrice', () => {
    it('should accept valid prices', () => {
      expect(isValidPrice(0)).toBe(true);           // Free tier
      expect(isValidPrice(999)).toBe(true);         // $9.99
      expect(isValidPrice(9900)).toBe(true);        // $99.00
      expect(isValidPrice(99999999)).toBe(true);    // Max price
    });
    
    it('should reject invalid prices', () => {
      expect(isValidPrice(-1)).toBe(false);         // Negative
      expect(isValidPrice(99999999 + 1)).toBe(false); // Over max
      expect(isValidPrice(9.99)).toBe(false);       // Not integer
      expect(isValidPrice(NaN)).toBe(false);        // NaN
      expect(isValidPrice(Infinity)).toBe(false);   // Infinity
    });
    
    it('should validate boundary values', () => {
      expect(isValidPrice(MIN_PRICE)).toBe(true);
      expect(isValidPrice(MAX_PRICE)).toBe(true);
      expect(isValidPrice(MIN_PRICE - 1)).toBe(false);
      expect(isValidPrice(MAX_PRICE + 1)).toBe(false);
    });
  });
  
  describe('isValidCurrency', () => {
    it('should accept valid currency codes', () => {
      expect(isValidCurrency('usd')).toBe(true);
      expect(isValidCurrency('USD')).toBe(true);
      expect(isValidCurrency('eur')).toBe(true);
      expect(isValidCurrency('gbp')).toBe(true);
      expect(isValidCurrency('jpy')).toBe(true);
    });
    
    it('should reject invalid currency codes', () => {
      expect(isValidCurrency('xxx')).toBe(false);
      expect(isValidCurrency('')).toBe(false);
      expect(isValidCurrency('dollar')).toBe(false);
      expect(isValidCurrency('$')).toBe(false);
    });
  });
  
  describe('isValidFeatures', () => {
    it('should accept valid features array', () => {
      expect(isValidFeatures(['feature1', 'feature2'])).toBe(true);
      expect(isValidFeatures(['single'])).toBe(true);
      expect(isValidFeatures([])).toBe(true);
    });
    
    it('should reject invalid features', () => {
      expect(isValidFeatures([''])).toBe(false);           // Empty string
      expect(isValidFeatures(['  '])).toBe(false);         // Whitespace only
      expect(isValidFeatures(null as unknown as string[])).toBe(false);
      expect(isValidFeatures('feature' as unknown as string[])).toBe(false);
    });
    
    it('should reject too many features', () => {
      const tooManyFeatures = Array(MAX_FEATURES_PER_PLAN + 1).fill('feature');
      expect(isValidFeatures(tooManyFeatures)).toBe(false);
      
      const maxFeatures = Array(MAX_FEATURES_PER_PLAN).fill('feature');
      expect(isValidFeatures(maxFeatures)).toBe(true);
    });
  });
  
  describe('isValidLimits', () => {
    it('should accept valid limits object', () => {
      expect(isValidLimits({ users: 10, storage_gb: 100 })).toBe(true);
      expect(isValidLimits({ single: 1 })).toBe(true);
      expect(isValidLimits({})).toBe(true);
      expect(isValidLimits({ unlimited: 0 })).toBe(true);
    });
    
    it('should reject invalid limits', () => {
      expect(isValidLimits({ users: -1 })).toBe(false);           // Negative
      expect(isValidLimits({ users: 1.5 })).toBe(false);          // Not integer
      expect(isValidLimits({ '': 10 })).toBe(false);              // Empty key
      expect(isValidLimits(null as unknown as Record<string, number>)).toBe(false);
      expect(isValidLimits([] as unknown as Record<string, number>)).toBe(false);
    });
    
    it('should reject too many limits', () => {
      const tooManyLimits: Record<string, number> = {};
      for (let i = 0; i <= MAX_LIMITS_PER_PLAN; i++) {
        tooManyLimits[`limit_${i}`] = i;
      }
      expect(isValidLimits(tooManyLimits)).toBe(false);
      
      const maxLimits: Record<string, number> = {};
      for (let i = 0; i < MAX_LIMITS_PER_PLAN; i++) {
        maxLimits[`limit_${i}`] = i;
      }
      expect(isValidLimits(maxLimits)).toBe(true);
    });
  });
  
  describe('isValidPlanName', () => {
    it('should accept valid plan names', () => {
      expect(isValidPlanName('Pro')).toBe(true);
      expect(isValidPlanName('Enterprise')).toBe(true);
      expect(isValidPlanName('Free Tier')).toBe(true);
      expect(isValidPlanName('A')).toBe(true);  // Minimum length
    });
    
    it('should reject invalid plan names', () => {
      expect(isValidPlanName('')).toBe(false);
      expect(isValidPlanName('   ')).toBe(false);  // Whitespace only
      expect(isValidPlanName('A'.repeat(101))).toBe(false);  // Too long
      expect(isValidPlanName(123 as unknown as string)).toBe(false);
    });
    
    it('should accept maximum length name', () => {
      expect(isValidPlanName('A'.repeat(100))).toBe(true);
    });
  });
  
  describe('isValidStripePriceId', () => {
    it('should accept valid Stripe price IDs', () => {
      expect(isValidStripePriceId('price_1234567890abcdef')).toBe(true);
      expect(isValidStripePriceId('price_ABC123')).toBe(true);
    });
    
    it('should reject invalid Stripe price IDs', () => {
      expect(isValidStripePriceId('invalid')).toBe(false);
      expect(isValidStripePriceId('price_')).toBe(false);
      expect(isValidStripePriceId('prod_123')).toBe(false);
      expect(isValidStripePriceId('')).toBe(false);
    });
  });
  
  describe('isValidStripeProductId', () => {
    it('should accept valid Stripe product IDs', () => {
      expect(isValidStripeProductId('prod_1234567890abcdef')).toBe(true);
      expect(isValidStripeProductId('prod_ABC123')).toBe(true);
    });
    
    it('should reject invalid Stripe product IDs', () => {
      expect(isValidStripeProductId('invalid')).toBe(false);
      expect(isValidStripeProductId('prod_')).toBe(false);
      expect(isValidStripeProductId('price_123')).toBe(false);
      expect(isValidStripeProductId('')).toBe(false);
    });
  });
  
  describe('toBillingPlanResponse', () => {
    it('should convert billing plan to response format', () => {
      const plan: BillingPlan = {
        id: 'plan_test123',
        realm_id: 'realm_abc',
        name: 'Pro Plan',
        description: 'Professional tier',
        type: 'per_user',
        price_monthly: 999,
        price_yearly: 9990,
        currency: 'usd',
        features: ['feature1', 'feature2'],
        limits: { users: 10 },
        stripe_price_id_monthly: 'price_monthly123',
        stripe_price_id_yearly: 'price_yearly123',
        stripe_product_id: 'prod_123',
        status: 'active',
        trial_days: 14,
        is_default: true,
        sort_order: 1,
        metadata: {
          created_by: 'user_123',
          highlight_text: 'Most Popular'
        },
        created_at: '2026-01-25T10:00:00Z',
        updated_at: '2026-01-26T10:00:00Z'
      };
      
      const response = toBillingPlanResponse(plan);
      
      expect(response.id).toBe(plan.id);
      expect(response.realm_id).toBe(plan.realm_id);
      expect(response.name).toBe(plan.name);
      expect(response.description).toBe(plan.description);
      expect(response.type).toBe(plan.type);
      expect(response.price_monthly).toBe(plan.price_monthly);
      expect(response.price_yearly).toBe(plan.price_yearly);
      expect(response.currency).toBe(plan.currency);
      expect(response.features).toEqual(plan.features);
      expect(response.limits).toEqual(plan.limits);
      expect(response.stripe_price_id_monthly).toBe(plan.stripe_price_id_monthly);
      expect(response.stripe_price_id_yearly).toBe(plan.stripe_price_id_yearly);
      expect(response.status).toBe(plan.status);
      expect(response.trial_days).toBe(plan.trial_days);
      expect(response.is_default).toBe(plan.is_default);
      expect(response.sort_order).toBe(plan.sort_order);
      expect(response.highlight_text).toBe('Most Popular');
      expect(response.created_at).toBe(plan.created_at);
      expect(response.updated_at).toBe(plan.updated_at);
      
      // Should not include stripe_product_id or full metadata
      expect((response as unknown as { stripe_product_id?: string }).stripe_product_id).toBeUndefined();
      expect((response as unknown as { metadata?: unknown }).metadata).toBeUndefined();
    });
    
    it('should handle plan without optional fields', () => {
      const plan: BillingPlan = {
        id: 'plan_test123',
        realm_id: 'realm_abc',
        name: 'Basic',
        type: 'flat_rate',
        price_monthly: 0,
        price_yearly: 0,
        currency: 'usd',
        features: [],
        limits: {},
        status: 'active',
        created_at: '2026-01-25T10:00:00Z'
      };
      
      const response = toBillingPlanResponse(plan);
      
      expect(response.description).toBeUndefined();
      expect(response.stripe_price_id_monthly).toBeUndefined();
      expect(response.stripe_price_id_yearly).toBeUndefined();
      expect(response.trial_days).toBeUndefined();
      expect(response.is_default).toBeUndefined();
      expect(response.sort_order).toBeUndefined();
      expect(response.highlight_text).toBeUndefined();
      expect(response.updated_at).toBeUndefined();
    });
  });
  
  describe('calculateYearlySavings', () => {
    it('should calculate correct savings percentage', () => {
      // $10/month = $120/year, yearly price $100 = 16.67% savings
      expect(calculateYearlySavings(1000, 10000)).toBe(17);
      
      // $99/month = $1188/year, yearly price $990 = 16.67% savings
      expect(calculateYearlySavings(9900, 99000)).toBe(17);
      
      // 2 months free (10 months price for yearly)
      expect(calculateYearlySavings(1000, 10000)).toBe(17);
    });
    
    it('should return 0 for free plans', () => {
      expect(calculateYearlySavings(0, 0)).toBe(0);
    });
    
    it('should return 0 when yearly is more expensive', () => {
      expect(calculateYearlySavings(1000, 15000)).toBe(0);
    });
    
    it('should return 0 when prices are equal', () => {
      expect(calculateYearlySavings(1000, 12000)).toBe(0);
    });
  });
  
  describe('formatPrice', () => {
    it('should format USD prices correctly', () => {
      expect(formatPrice(999, 'usd')).toBe('$9.99');
      expect(formatPrice(9900, 'usd')).toBe('$99.00');
      expect(formatPrice(0, 'usd')).toBe('$0.00');
    });
    
    it('should format EUR prices correctly', () => {
      expect(formatPrice(999, 'eur')).toMatch(/€|EUR/);
    });
    
    it('should format GBP prices correctly', () => {
      expect(formatPrice(999, 'gbp')).toMatch(/£|GBP/);
    });
  });
  
  describe('hasFeature', () => {
    const plan: BillingPlan = {
      id: 'plan_test',
      realm_id: 'realm_abc',
      name: 'Pro',
      type: 'per_user',
      price_monthly: 999,
      price_yearly: 9990,
      currency: 'usd',
      features: ['sso', 'api_access', 'priority_support'],
      limits: {},
      status: 'active',
      created_at: '2026-01-25T10:00:00Z'
    };
    
    it('should return true for included features', () => {
      expect(hasFeature(plan, 'sso')).toBe(true);
      expect(hasFeature(plan, 'api_access')).toBe(true);
      expect(hasFeature(plan, 'priority_support')).toBe(true);
    });
    
    it('should return false for missing features', () => {
      expect(hasFeature(plan, 'custom_branding')).toBe(false);
      expect(hasFeature(plan, '')).toBe(false);
    });
  });
  
  describe('getLimit', () => {
    const plan: BillingPlan = {
      id: 'plan_test',
      realm_id: 'realm_abc',
      name: 'Pro',
      type: 'per_user',
      price_monthly: 999,
      price_yearly: 9990,
      currency: 'usd',
      features: [],
      limits: { users: 10, storage_gb: 100, api_calls: 10000 },
      status: 'active',
      created_at: '2026-01-25T10:00:00Z'
    };
    
    it('should return limit value for defined limits', () => {
      expect(getLimit(plan, 'users')).toBe(10);
      expect(getLimit(plan, 'storage_gb')).toBe(100);
      expect(getLimit(plan, 'api_calls')).toBe(10000);
    });
    
    it('should return undefined for undefined limits', () => {
      expect(getLimit(plan, 'bandwidth')).toBeUndefined();
      expect(getLimit(plan, '')).toBeUndefined();
    });
  });
  
  describe('isWithinLimit', () => {
    const plan: BillingPlan = {
      id: 'plan_test',
      realm_id: 'realm_abc',
      name: 'Pro',
      type: 'per_user',
      price_monthly: 999,
      price_yearly: 9990,
      currency: 'usd',
      features: [],
      limits: { users: 10 },
      status: 'active',
      created_at: '2026-01-25T10:00:00Z'
    };
    
    it('should return true when within limit', () => {
      expect(isWithinLimit(plan, 'users', 5)).toBe(true);
      expect(isWithinLimit(plan, 'users', 10)).toBe(true);
    });
    
    it('should return false when exceeding limit', () => {
      expect(isWithinLimit(plan, 'users', 11)).toBe(false);
      expect(isWithinLimit(plan, 'users', 100)).toBe(false);
    });
    
    it('should return true for undefined limits (unlimited)', () => {
      expect(isWithinLimit(plan, 'storage_gb', 1000000)).toBe(true);
    });
  });
  
  describe('comparePlansBySortOrder', () => {
    it('should sort plans by sort_order', () => {
      const plans: BillingPlan[] = [
        { id: 'plan_3', sort_order: 3 } as BillingPlan,
        { id: 'plan_1', sort_order: 1 } as BillingPlan,
        { id: 'plan_2', sort_order: 2 } as BillingPlan
      ];
      
      const sorted = [...plans].sort(comparePlansBySortOrder);
      
      expect(sorted[0].id).toBe('plan_1');
      expect(sorted[1].id).toBe('plan_2');
      expect(sorted[2].id).toBe('plan_3');
    });
    
    it('should put plans without sort_order at the end', () => {
      const plans: BillingPlan[] = [
        { id: 'plan_no_order' } as BillingPlan,
        { id: 'plan_1', sort_order: 1 } as BillingPlan
      ];
      
      const sorted = [...plans].sort(comparePlansBySortOrder);
      
      expect(sorted[0].id).toBe('plan_1');
      expect(sorted[1].id).toBe('plan_no_order');
    });
  });
  
  describe('findPlanWithFeature', () => {
    const plans: BillingPlan[] = [
      {
        id: 'plan_basic',
        name: 'Basic',
        type: 'flat_rate',
        features: ['basic_support'],
        status: 'active',
        sort_order: 1
      } as BillingPlan,
      {
        id: 'plan_pro',
        name: 'Pro',
        type: 'per_user',
        features: ['basic_support', 'sso', 'api_access'],
        status: 'active',
        sort_order: 2
      } as BillingPlan,
      {
        id: 'plan_inactive',
        name: 'Inactive',
        type: 'flat_rate',
        features: ['sso'],
        status: 'inactive',
        sort_order: 0
      } as BillingPlan
    ];
    
    it('should find the first active plan with the feature', () => {
      const result = findPlanWithFeature(plans, 'sso');
      expect(result?.id).toBe('plan_pro');
    });
    
    it('should return undefined if no plan has the feature', () => {
      const result = findPlanWithFeature(plans, 'custom_branding');
      expect(result).toBeUndefined();
    });
    
    it('should not return inactive plans', () => {
      // plan_inactive has sso but is inactive
      const result = findPlanWithFeature(plans, 'sso');
      expect(result?.id).not.toBe('plan_inactive');
    });
  });
  
  describe('findCheapestPlanForLimits', () => {
    const plans: BillingPlan[] = [
      {
        id: 'plan_basic',
        realm_id: 'realm_test',
        name: 'Basic',
        type: 'flat_rate',
        price_monthly: 0,
        price_yearly: 0,
        currency: 'usd',
        features: [],
        limits: { users: 5, storage_gb: 10 },
        status: 'active',
        created_at: '2026-01-25T10:00:00Z'
      },
      {
        id: 'plan_pro',
        realm_id: 'realm_test',
        name: 'Pro',
        type: 'per_user',
        price_monthly: 999,
        price_yearly: 9990,
        currency: 'usd',
        features: [],
        limits: { users: 20, storage_gb: 100 },
        status: 'active',
        created_at: '2026-01-25T10:00:00Z'
      },
      {
        id: 'plan_enterprise',
        realm_id: 'realm_test',
        name: 'Enterprise',
        type: 'per_org',
        price_monthly: 9999,
        price_yearly: 99990,
        currency: 'usd',
        features: [],
        limits: { users: 1000, storage_gb: 1000 },
        status: 'active',
        created_at: '2026-01-25T10:00:00Z'
      }
    ];
    
    it('should find cheapest plan meeting requirements', () => {
      const result = findCheapestPlanForLimits(plans, { users: 10 });
      expect(result?.id).toBe('plan_pro');
    });
    
    it('should return free plan if it meets requirements', () => {
      const result = findCheapestPlanForLimits(plans, { users: 3 });
      expect(result?.id).toBe('plan_basic');
    });
    
    it('should return undefined if no plan meets requirements', () => {
      const result = findCheapestPlanForLimits(plans, { users: 10000 });
      expect(result).toBeUndefined();
    });
    
    it('should use yearly price when specified', () => {
      const result = findCheapestPlanForLimits(plans, { users: 10 }, 'yearly');
      expect(result?.id).toBe('plan_pro');
    });
  });
});
