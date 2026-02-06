/**
 * Subscription Model Tests
 * Tests for subscription model utilities and helper functions
 * 
 * Validates: Requirements 7.4 (Subscriptions)
 * ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
 */

import {
  generateSubscriptionId,
  isValidSubscriptionStatus,
  isValidStripeSubscriptionId,
  isValidStripeCustomerId,
  isValidISODate,
  isValidTenantId,
  isValidPlanId,
  isValidQuantity,
  toSubscriptionResponse,
  isSubscriptionActive,
  isInTrialPeriod,
  isSubscriptionPastDue,
  isSubscriptionCanceled,
  willCancelAtPeriodEnd,
  getDaysRemainingInPeriod,
  getDaysRemainingInTrial,
  hasPeriodEnded,
  formatSubscriptionStatus,
  getSubscriptionStatusColor,
  compareSubscriptionsByDate,
  mapStripeStatus,
  SUBSCRIPTION_ID_PREFIX,
  SUBSCRIPTION_STATUSES,
  Subscription,
  SubscriptionStatus
} from './subscription.model';

describe('Subscription Model Utilities', () => {
  describe('generateSubscriptionId', () => {
    it('should generate ID with sub_ prefix', () => {
      const id = generateSubscriptionId();
      expect(id).toMatch(/^sub_[a-f0-9]{24}$/);
      expect(id.startsWith(SUBSCRIPTION_ID_PREFIX)).toBe(true);
    });
    
    it('should generate unique IDs', () => {
      const ids = new Set<string>();
      for (let i = 0; i < 100; i++) {
        ids.add(generateSubscriptionId());
      }
      expect(ids.size).toBe(100);
    });
  });
  
  describe('isValidSubscriptionStatus', () => {
    it('should accept valid subscription statuses', () => {
      expect(isValidSubscriptionStatus('active')).toBe(true);
      expect(isValidSubscriptionStatus('past_due')).toBe(true);
      expect(isValidSubscriptionStatus('canceled')).toBe(true);
      expect(isValidSubscriptionStatus('trialing')).toBe(true);
    });
    
    it('should reject invalid subscription statuses', () => {
      expect(isValidSubscriptionStatus('invalid')).toBe(false);
      expect(isValidSubscriptionStatus('ACTIVE')).toBe(false);
      expect(isValidSubscriptionStatus('')).toBe(false);
      expect(isValidSubscriptionStatus('pending')).toBe(false);
      expect(isValidSubscriptionStatus('expired')).toBe(false);
    });
    
    it('should validate all defined statuses', () => {
      for (const status of SUBSCRIPTION_STATUSES) {
        expect(isValidSubscriptionStatus(status)).toBe(true);
      }
    });
  });
  
  describe('isValidStripeSubscriptionId', () => {
    it('should accept valid Stripe subscription IDs', () => {
      expect(isValidStripeSubscriptionId('sub_1234567890abcdef')).toBe(true);
      expect(isValidStripeSubscriptionId('sub_ABC123xyz')).toBe(true);
      expect(isValidStripeSubscriptionId('sub_a')).toBe(true);
    });
    
    it('should reject invalid Stripe subscription IDs', () => {
      expect(isValidStripeSubscriptionId('invalid')).toBe(false);
      expect(isValidStripeSubscriptionId('sub_')).toBe(false);
      expect(isValidStripeSubscriptionId('cus_123')).toBe(false);
      expect(isValidStripeSubscriptionId('price_123')).toBe(false);
      expect(isValidStripeSubscriptionId('')).toBe(false);
    });
  });
  
  describe('isValidStripeCustomerId', () => {
    it('should accept valid Stripe customer IDs', () => {
      expect(isValidStripeCustomerId('cus_1234567890abcdef')).toBe(true);
      expect(isValidStripeCustomerId('cus_ABC123xyz')).toBe(true);
      expect(isValidStripeCustomerId('cus_a')).toBe(true);
    });
    
    it('should reject invalid Stripe customer IDs', () => {
      expect(isValidStripeCustomerId('invalid')).toBe(false);
      expect(isValidStripeCustomerId('cus_')).toBe(false);
      expect(isValidStripeCustomerId('sub_123')).toBe(false);
      expect(isValidStripeCustomerId('')).toBe(false);
    });
  });
  
  describe('isValidISODate', () => {
    it('should accept valid ISO 8601 dates', () => {
      expect(isValidISODate('2026-01-25T10:00:00Z')).toBe(true);
      expect(isValidISODate('2026-01-25T10:00:00.000Z')).toBe(true);
      expect(isValidISODate('2026-01-25T10:00:00+00:00')).toBe(true);
    });
    
    it('should reject invalid dates', () => {
      expect(isValidISODate('invalid')).toBe(false);
      expect(isValidISODate('2026-01-25')).toBe(false); // Missing time
      expect(isValidISODate('')).toBe(false);
      expect(isValidISODate(123 as unknown as string)).toBe(false);
    });
  });
  
  describe('isValidTenantId', () => {
    it('should accept valid tenant IDs', () => {
      expect(isValidTenantId('tenant_123')).toBe(true);
      expect(isValidTenantId('abc')).toBe(true);
      expect(isValidTenantId('my-tenant-id')).toBe(true);
    });
    
    it('should reject invalid tenant IDs', () => {
      expect(isValidTenantId('')).toBe(false);
      expect(isValidTenantId('   ')).toBe(false);
      expect(isValidTenantId(123 as unknown as string)).toBe(false);
    });
  });
  
  describe('isValidPlanId', () => {
    it('should accept valid plan IDs', () => {
      expect(isValidPlanId('plan_1234567890abcdef12345678')).toBe(true);
      expect(isValidPlanId('plan_abcdef1234567890abcdef12')).toBe(true);
    });
    
    it('should reject invalid plan IDs', () => {
      expect(isValidPlanId('invalid')).toBe(false);
      expect(isValidPlanId('plan_')).toBe(false);
      expect(isValidPlanId('plan_123')).toBe(false); // Too short
      expect(isValidPlanId('sub_1234567890abcdef12345678')).toBe(false);
      expect(isValidPlanId('')).toBe(false);
    });
  });
  
  describe('isValidQuantity', () => {
    it('should accept valid quantities', () => {
      expect(isValidQuantity(1)).toBe(true);
      expect(isValidQuantity(10)).toBe(true);
      expect(isValidQuantity(100)).toBe(true);
      expect(isValidQuantity(100000)).toBe(true);
    });
    
    it('should reject invalid quantities', () => {
      expect(isValidQuantity(0)).toBe(false);
      expect(isValidQuantity(-1)).toBe(false);
      expect(isValidQuantity(100001)).toBe(false);
      expect(isValidQuantity(1.5)).toBe(false);
      expect(isValidQuantity(NaN)).toBe(false);
    });
  });
  
  describe('toSubscriptionResponse', () => {
    it('should convert subscription to response format', () => {
      const subscription: Subscription = {
        id: 'sub_test123',
        tenant_id: 'tenant_abc',
        plan_id: 'plan_1234567890abcdef12345678',
        stripe_subscription_id: 'sub_stripe123',
        stripe_customer_id: 'cus_stripe456',
        status: 'active',
        current_period_start: '2026-01-01T00:00:00Z',
        current_period_end: '2026-02-01T00:00:00Z',
        cancel_at_period_end: false,
        trial_start: '2026-01-01T00:00:00Z',
        trial_end: '2026-01-15T00:00:00Z',
        quantity: 5,
        metadata: {
          created_by: 'user_123',
          payment_method_id: 'pm_123'
        },
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-15T00:00:00Z'
      };
      
      const response = toSubscriptionResponse(subscription);
      
      expect(response.id).toBe(subscription.id);
      expect(response.tenant_id).toBe(subscription.tenant_id);
      expect(response.plan_id).toBe(subscription.plan_id);
      expect(response.stripe_subscription_id).toBe(subscription.stripe_subscription_id);
      expect(response.status).toBe(subscription.status);
      expect(response.current_period_start).toBe(subscription.current_period_start);
      expect(response.current_period_end).toBe(subscription.current_period_end);
      expect(response.cancel_at_period_end).toBe(subscription.cancel_at_period_end);
      expect(response.trial_start).toBe(subscription.trial_start);
      expect(response.trial_end).toBe(subscription.trial_end);
      expect(response.quantity).toBe(subscription.quantity);
      expect(response.created_at).toBe(subscription.created_at);
      expect(response.updated_at).toBe(subscription.updated_at);
      
      // Should not include internal fields
      expect((response as unknown as { stripe_customer_id?: string }).stripe_customer_id).toBeUndefined();
      expect((response as unknown as { metadata?: unknown }).metadata).toBeUndefined();
    });
    
    it('should handle subscription without optional fields', () => {
      const subscription: Subscription = {
        id: 'sub_test123',
        tenant_id: 'tenant_abc',
        plan_id: 'plan_1234567890abcdef12345678',
        stripe_subscription_id: 'sub_stripe123',
        status: 'active',
        current_period_start: '2026-01-01T00:00:00Z',
        current_period_end: '2026-02-01T00:00:00Z',
        created_at: '2026-01-01T00:00:00Z'
      };
      
      const response = toSubscriptionResponse(subscription);
      
      expect(response.cancel_at_period_end).toBeUndefined();
      expect(response.canceled_at).toBeUndefined();
      expect(response.trial_start).toBeUndefined();
      expect(response.trial_end).toBeUndefined();
      expect(response.quantity).toBeUndefined();
      expect(response.updated_at).toBeUndefined();
    });
  });
  
  describe('isSubscriptionActive', () => {
    it('should return true for active subscriptions', () => {
      const subscription = { status: 'active' } as Subscription;
      expect(isSubscriptionActive(subscription)).toBe(true);
    });
    
    it('should return true for trialing subscriptions', () => {
      const subscription = { status: 'trialing' } as Subscription;
      expect(isSubscriptionActive(subscription)).toBe(true);
    });
    
    it('should return false for past_due subscriptions', () => {
      const subscription = { status: 'past_due' } as Subscription;
      expect(isSubscriptionActive(subscription)).toBe(false);
    });
    
    it('should return false for canceled subscriptions', () => {
      const subscription = { status: 'canceled' } as Subscription;
      expect(isSubscriptionActive(subscription)).toBe(false);
    });
  });
  
  describe('isInTrialPeriod', () => {
    it('should return true when in trial period', () => {
      const futureDate = new Date();
      futureDate.setDate(futureDate.getDate() + 7);
      
      const subscription: Subscription = {
        status: 'trialing',
        trial_end: futureDate.toISOString()
      } as Subscription;
      
      expect(isInTrialPeriod(subscription)).toBe(true);
    });
    
    it('should return false when trial has ended', () => {
      const pastDate = new Date();
      pastDate.setDate(pastDate.getDate() - 7);
      
      const subscription: Subscription = {
        status: 'trialing',
        trial_end: pastDate.toISOString()
      } as Subscription;
      
      expect(isInTrialPeriod(subscription)).toBe(false);
    });
    
    it('should return false when not trialing', () => {
      const subscription: Subscription = {
        status: 'active',
        trial_end: new Date().toISOString()
      } as Subscription;
      
      expect(isInTrialPeriod(subscription)).toBe(false);
    });
    
    it('should return false when no trial_end', () => {
      const subscription: Subscription = {
        status: 'trialing'
      } as Subscription;
      
      expect(isInTrialPeriod(subscription)).toBe(false);
    });
  });
  
  describe('isSubscriptionPastDue', () => {
    it('should return true for past_due subscriptions', () => {
      const subscription = { status: 'past_due' } as Subscription;
      expect(isSubscriptionPastDue(subscription)).toBe(true);
    });
    
    it('should return false for other statuses', () => {
      expect(isSubscriptionPastDue({ status: 'active' } as Subscription)).toBe(false);
      expect(isSubscriptionPastDue({ status: 'canceled' } as Subscription)).toBe(false);
      expect(isSubscriptionPastDue({ status: 'trialing' } as Subscription)).toBe(false);
    });
  });
  
  describe('isSubscriptionCanceled', () => {
    it('should return true for canceled subscriptions', () => {
      const subscription = { status: 'canceled' } as Subscription;
      expect(isSubscriptionCanceled(subscription)).toBe(true);
    });
    
    it('should return false for other statuses', () => {
      expect(isSubscriptionCanceled({ status: 'active' } as Subscription)).toBe(false);
      expect(isSubscriptionCanceled({ status: 'past_due' } as Subscription)).toBe(false);
      expect(isSubscriptionCanceled({ status: 'trialing' } as Subscription)).toBe(false);
    });
  });
  
  describe('willCancelAtPeriodEnd', () => {
    it('should return true when cancel_at_period_end is true', () => {
      const subscription = { cancel_at_period_end: true } as Subscription;
      expect(willCancelAtPeriodEnd(subscription)).toBe(true);
    });
    
    it('should return false when cancel_at_period_end is false', () => {
      const subscription = { cancel_at_period_end: false } as Subscription;
      expect(willCancelAtPeriodEnd(subscription)).toBe(false);
    });
    
    it('should return false when cancel_at_period_end is undefined', () => {
      const subscription = {} as Subscription;
      expect(willCancelAtPeriodEnd(subscription)).toBe(false);
    });
  });
  
  describe('getDaysRemainingInPeriod', () => {
    it('should return correct days remaining', () => {
      const futureDate = new Date();
      futureDate.setDate(futureDate.getDate() + 10);
      
      const subscription: Subscription = {
        current_period_end: futureDate.toISOString()
      } as Subscription;
      
      const days = getDaysRemainingInPeriod(subscription);
      expect(days).toBeGreaterThanOrEqual(9);
      expect(days).toBeLessThanOrEqual(11);
    });
    
    it('should return 0 when period has ended', () => {
      const pastDate = new Date();
      pastDate.setDate(pastDate.getDate() - 5);
      
      const subscription: Subscription = {
        current_period_end: pastDate.toISOString()
      } as Subscription;
      
      expect(getDaysRemainingInPeriod(subscription)).toBe(0);
    });
  });
  
  describe('getDaysRemainingInTrial', () => {
    it('should return correct days remaining in trial', () => {
      const futureDate = new Date();
      futureDate.setDate(futureDate.getDate() + 7);
      
      const subscription: Subscription = {
        trial_end: futureDate.toISOString()
      } as Subscription;
      
      const days = getDaysRemainingInTrial(subscription);
      expect(days).toBeGreaterThanOrEqual(6);
      expect(days).toBeLessThanOrEqual(8);
    });
    
    it('should return 0 when trial has ended', () => {
      const pastDate = new Date();
      pastDate.setDate(pastDate.getDate() - 3);
      
      const subscription: Subscription = {
        trial_end: pastDate.toISOString()
      } as Subscription;
      
      expect(getDaysRemainingInTrial(subscription)).toBe(0);
    });
    
    it('should return 0 when no trial_end', () => {
      const subscription = {} as Subscription;
      expect(getDaysRemainingInTrial(subscription)).toBe(0);
    });
  });
  
  describe('hasPeriodEnded', () => {
    it('should return true when period has ended', () => {
      const pastDate = new Date();
      pastDate.setDate(pastDate.getDate() - 1);
      
      const subscription: Subscription = {
        current_period_end: pastDate.toISOString()
      } as Subscription;
      
      expect(hasPeriodEnded(subscription)).toBe(true);
    });
    
    it('should return false when period has not ended', () => {
      const futureDate = new Date();
      futureDate.setDate(futureDate.getDate() + 10);
      
      const subscription: Subscription = {
        current_period_end: futureDate.toISOString()
      } as Subscription;
      
      expect(hasPeriodEnded(subscription)).toBe(false);
    });
  });
  
  describe('formatSubscriptionStatus', () => {
    it('should format statuses correctly', () => {
      expect(formatSubscriptionStatus('active')).toBe('Active');
      expect(formatSubscriptionStatus('past_due')).toBe('Past Due');
      expect(formatSubscriptionStatus('canceled')).toBe('Canceled');
      expect(formatSubscriptionStatus('trialing')).toBe('Trial');
    });
  });
  
  describe('getSubscriptionStatusColor', () => {
    it('should return correct colors for statuses', () => {
      expect(getSubscriptionStatusColor('active')).toBe('green');
      expect(getSubscriptionStatusColor('past_due')).toBe('yellow');
      expect(getSubscriptionStatusColor('canceled')).toBe('red');
      expect(getSubscriptionStatusColor('trialing')).toBe('blue');
    });
  });
  
  describe('compareSubscriptionsByDate', () => {
    it('should sort subscriptions by date (newest first)', () => {
      const subscriptions: Subscription[] = [
        { id: 'sub_1', created_at: '2026-01-01T00:00:00Z' } as Subscription,
        { id: 'sub_3', created_at: '2026-03-01T00:00:00Z' } as Subscription,
        { id: 'sub_2', created_at: '2026-02-01T00:00:00Z' } as Subscription
      ];
      
      const sorted = [...subscriptions].sort(compareSubscriptionsByDate);
      
      expect(sorted[0].id).toBe('sub_3');
      expect(sorted[1].id).toBe('sub_2');
      expect(sorted[2].id).toBe('sub_1');
    });
  });
  
  describe('mapStripeStatus', () => {
    it('should map Stripe statuses correctly', () => {
      expect(mapStripeStatus('active')).toBe('active');
      expect(mapStripeStatus('past_due')).toBe('past_due');
      expect(mapStripeStatus('canceled')).toBe('canceled');
      expect(mapStripeStatus('trialing')).toBe('trialing');
    });
    
    it('should map unpaid to past_due', () => {
      expect(mapStripeStatus('unpaid')).toBe('past_due');
    });
    
    it('should map incomplete to past_due', () => {
      expect(mapStripeStatus('incomplete')).toBe('past_due');
    });
    
    it('should map incomplete_expired to canceled', () => {
      expect(mapStripeStatus('incomplete_expired')).toBe('canceled');
    });
    
    it('should map paused to canceled', () => {
      expect(mapStripeStatus('paused')).toBe('canceled');
    });
    
    it('should default unknown statuses to canceled', () => {
      expect(mapStripeStatus('unknown')).toBe('canceled');
      expect(mapStripeStatus('')).toBe('canceled');
    });
  });
});
