/**
 * BillingService Tests
 * 
 * Tests for the integrated billing management service.
 * Uses mocked Stripe client for testing without real API calls.
 * 
 * Validates: Requirements 7.2, 7.4, 7.5, 7.6
 */

// Mock uuid before imports
jest.mock('uuid', () => ({
  v4: jest.fn().mockReturnValue('12345678-1234-1234-1234-123456789012')
}));

// Mock repositories BEFORE imports
jest.mock('../repositories/billing-plan.repository');
jest.mock('../repositories/subscription.repository');
jest.mock('./usage.service');
jest.mock('./audit.service', () => ({
  logAuditEvent: jest.fn().mockResolvedValue(undefined),
  AuditEventType: { ADMIN_ACTION: 'admin_action' },
  AuditResult: { SUCCESS: 'success' }
}));

import Stripe from 'stripe';
import {
  BillingService,
  BillingServiceError,
  BillingErrorCode,
  CreatePlanServiceInput,
  SubscribeServiceInput,
  CancelSubscriptionInput
} from './billing.service';
import * as billingPlanRepository from '../repositories/billing-plan.repository';
import * as subscriptionRepository from '../repositories/subscription.repository';
import * as usageService from './usage.service';
import { BillingPlan } from '../models/billing-plan.model';
import { Subscription } from '../models/subscription.model';

// Test data
const testRealmId = 'realm_test123';
const testTenantId = 'tenant_test456';
const testPlanId = 'plan_abc123def456789012';
const testSubscriptionId = 'sub_test789';

const mockPlan: BillingPlan = {
  id: testPlanId,
  realm_id: testRealmId,
  name: 'Pro Plan',
  description: 'Professional tier',
  type: 'flat_rate',
  price_monthly: 2900,
  price_yearly: 29000,
  currency: 'usd',
  features: ['feature_a', 'feature_b', 'advanced_analytics'],
  limits: { users: 100, api_calls: 100000, storage_gb: 50 },
  stripe_price_id_monthly: 'price_monthly123',
  stripe_price_id_yearly: 'price_yearly123',
  stripe_product_id: 'prod_test123',
  status: 'active',
  trial_days: 14,
  is_default: false,
  sort_order: 1,
  created_at: new Date().toISOString()
};

const mockSubscription: Subscription = {
  id: testSubscriptionId,
  tenant_id: testTenantId,
  plan_id: testPlanId,
  stripe_subscription_id: 'sub_stripe123',
  stripe_customer_id: 'cus_stripe123',
  status: 'active',
  current_period_start: new Date().toISOString(),
  current_period_end: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
  created_at: new Date().toISOString(),
  metadata: { custom_fields: { realm_id: testRealmId } }
};

// Create mock Stripe instance
const createMockStripe = () => ({
  products: { create: jest.fn() },
  prices: { create: jest.fn() },
  customers: { search: jest.fn(), create: jest.fn(), update: jest.fn() },
  paymentMethods: { attach: jest.fn() },
  subscriptions: { create: jest.fn(), update: jest.fn(), cancel: jest.fn() },
  webhooks: { constructEvent: jest.fn() }
});

const mockedBillingPlanRepo = billingPlanRepository as jest.Mocked<typeof billingPlanRepository>;
const mockedSubscriptionRepo = subscriptionRepository as jest.Mocked<typeof subscriptionRepository>;
const mockedUsageService = usageService as jest.Mocked<typeof usageService>;

describe('BillingService', () => {
  let billingService: BillingService;
  let mockStripe: ReturnType<typeof createMockStripe>;

  beforeEach(() => {
    jest.clearAllMocks();
    mockStripe = createMockStripe();
    billingService = new BillingService(mockStripe as unknown as Stripe);
  });

  // ==========================================================================
  // Plan Management Tests
  // ==========================================================================

  describe('createPlan', () => {
    it('should create a billing plan without Stripe product', async () => {
      const input: CreatePlanServiceInput = {
        realm_id: testRealmId,
        name: 'Basic Plan',
        type: 'flat_rate',
        price_monthly: 1900,
        price_yearly: 19000,
        features: ['feature_a'],
        limits: { users: 10 },
        create_stripe_product: false
      };

      mockedBillingPlanRepo.createBillingPlan.mockResolvedValue({
        ...mockPlan,
        name: 'Basic Plan',
        price_monthly: 1900,
        price_yearly: 19000
      });

      const result = await billingService.createPlan(input);

      expect(result.name).toBe('Basic Plan');
      expect(result.price_monthly).toBe(1900);
      expect(mockedBillingPlanRepo.createBillingPlan).toHaveBeenCalledTimes(1);
      expect(mockStripe.products.create).not.toHaveBeenCalled();
    });

    it('should create a billing plan with Stripe product', async () => {
      const input: CreatePlanServiceInput = {
        realm_id: testRealmId,
        name: 'Pro Plan',
        type: 'flat_rate',
        price_monthly: 2900,
        price_yearly: 29000,
        features: ['feature_a', 'feature_b'],
        limits: { users: 100 },
        create_stripe_product: true
      };

      mockStripe.products.create.mockResolvedValue({ id: 'prod_new123' });
      mockStripe.prices.create
        .mockResolvedValueOnce({ id: 'price_monthly_new' })
        .mockResolvedValueOnce({ id: 'price_yearly_new' });

      mockedBillingPlanRepo.createBillingPlan.mockResolvedValue({
        ...mockPlan,
        stripe_product_id: 'prod_new123',
        stripe_price_id_monthly: 'price_monthly_new',
        stripe_price_id_yearly: 'price_yearly_new'
      });

      const result = await billingService.createPlan(input);

      expect(mockStripe.products.create).toHaveBeenCalledTimes(1);
      expect(mockStripe.prices.create).toHaveBeenCalledTimes(2);
      expect(result.stripe_price_id_monthly).toBe('price_monthly_new');
    });

    it('should throw error when Stripe product creation fails', async () => {
      const input: CreatePlanServiceInput = {
        realm_id: testRealmId,
        name: 'Pro Plan',
        type: 'flat_rate',
        price_monthly: 2900,
        price_yearly: 29000,
        features: ['feature_a'],
        limits: { users: 100 },
        create_stripe_product: true
      };

      mockStripe.products.create.mockRejectedValue(new Error('Stripe API error'));

      await expect(billingService.createPlan(input)).rejects.toThrow(BillingServiceError);
    });
  });

  describe('getPlan', () => {
    it('should return plan when found', async () => {
      mockedBillingPlanRepo.getBillingPlanById.mockResolvedValue(mockPlan);

      const result = await billingService.getPlan(testRealmId, testPlanId);

      expect(result).not.toBeNull();
      expect(result?.id).toBe(testPlanId);
    });

    it('should return null when plan not found', async () => {
      mockedBillingPlanRepo.getBillingPlanById.mockResolvedValue(null);

      const result = await billingService.getPlan(testRealmId, 'nonexistent');

      expect(result).toBeNull();
    });
  });

  // ==========================================================================
  // Subscription Tests
  // ==========================================================================

  describe('subscribe', () => {
    const subscribeInput: SubscribeServiceInput = {
      tenant_id: testTenantId,
      plan_id: testPlanId,
      payment_method_id: 'pm_test123',
      realm_id: testRealmId
    };

    it('should create a subscription successfully', async () => {
      mockedBillingPlanRepo.getBillingPlanById.mockResolvedValue(mockPlan);
      mockedSubscriptionRepo.getActiveSubscription.mockResolvedValue(null);
      mockStripe.customers.search.mockResolvedValue({ data: [] });
      mockStripe.customers.create.mockResolvedValue({ id: 'cus_new123' });
      mockStripe.paymentMethods.attach.mockResolvedValue({});
      mockStripe.customers.update.mockResolvedValue({});
      mockStripe.subscriptions.create.mockResolvedValue({
        id: 'sub_new123',
        status: 'active',
        current_period_start: Math.floor(Date.now() / 1000),
        current_period_end: Math.floor(Date.now() / 1000) + 30 * 24 * 60 * 60
      });
      mockedSubscriptionRepo.createSubscription.mockResolvedValue(mockSubscription);

      const result = await billingService.subscribe(subscribeInput);

      expect(result.tenant_id).toBe(testTenantId);
      expect(result.status).toBe('active');
    });

    it('should throw error when plan not found', async () => {
      mockedBillingPlanRepo.getBillingPlanById.mockResolvedValue(null);

      await expect(billingService.subscribe(subscribeInput)).rejects.toThrow(BillingServiceError);
    });

    it('should throw error when tenant already has active subscription', async () => {
      mockedBillingPlanRepo.getBillingPlanById.mockResolvedValue(mockPlan);
      mockedSubscriptionRepo.getActiveSubscription.mockResolvedValue(mockSubscription);

      await expect(billingService.subscribe(subscribeInput)).rejects.toThrow(BillingServiceError);
    });
  });

  describe('cancelSubscription', () => {
    const cancelInput: CancelSubscriptionInput = {
      subscription_id: testSubscriptionId,
      tenant_id: testTenantId,
      canceled_by: 'user_admin123'
    };

    it('should cancel subscription immediately', async () => {
      mockedSubscriptionRepo.getSubscriptionById.mockResolvedValue(mockSubscription);
      mockStripe.subscriptions.cancel.mockResolvedValue({});
      mockedSubscriptionRepo.updateSubscription.mockResolvedValue({
        ...mockSubscription,
        status: 'canceled'
      });

      await billingService.cancelSubscription(cancelInput);

      expect(mockStripe.subscriptions.cancel).toHaveBeenCalledWith('sub_stripe123');
    });

    it('should cancel subscription at period end', async () => {
      mockedSubscriptionRepo.getSubscriptionById.mockResolvedValue(mockSubscription);
      mockStripe.subscriptions.update.mockResolvedValue({});
      mockedSubscriptionRepo.updateSubscription.mockResolvedValue({
        ...mockSubscription,
        cancel_at_period_end: true
      });

      await billingService.cancelSubscription({ ...cancelInput, cancel_at_period_end: true });

      expect(mockStripe.subscriptions.update).toHaveBeenCalledWith('sub_stripe123', {
        cancel_at_period_end: true
      });
    });

    it('should throw error when subscription not found', async () => {
      mockedSubscriptionRepo.getSubscriptionById.mockResolvedValue(null);

      await expect(billingService.cancelSubscription(cancelInput)).rejects.toThrow(BillingServiceError);
    });
  });

  // ==========================================================================
  // Entitlement Tests
  // ==========================================================================

  describe('checkEntitlement', () => {
    it('should return true when feature is included in plan', async () => {
      mockedSubscriptionRepo.getActiveSubscription.mockResolvedValue(mockSubscription);
      mockedBillingPlanRepo.getBillingPlanById.mockResolvedValue(mockPlan);

      const result = await billingService.checkEntitlement(testTenantId, 'feature_a');

      expect(result).toBe(true);
    });

    it('should return false when feature is not included in plan', async () => {
      mockedSubscriptionRepo.getActiveSubscription.mockResolvedValue(mockSubscription);
      mockedBillingPlanRepo.getBillingPlanById.mockResolvedValue(mockPlan);

      const result = await billingService.checkEntitlement(testTenantId, 'premium_feature');

      expect(result).toBe(false);
    });

    it('should return false when no active subscription', async () => {
      mockedSubscriptionRepo.getActiveSubscription.mockResolvedValue(null);

      const result = await billingService.checkEntitlement(testTenantId, 'feature_a');

      expect(result).toBe(false);
    });
  });

  describe('checkLimit', () => {
    it('should return access granted when within limit', async () => {
      mockedSubscriptionRepo.getActiveSubscription.mockResolvedValue(mockSubscription);
      mockedBillingPlanRepo.getBillingPlanById.mockResolvedValue(mockPlan);

      const result = await billingService.checkLimit(testTenantId, 'users', 50);

      expect(result.has_access).toBe(true);
      expect(result.limit).toBe(100);
    });

    it('should return access denied when limit exceeded', async () => {
      mockedSubscriptionRepo.getActiveSubscription.mockResolvedValue(mockSubscription);
      mockedBillingPlanRepo.getBillingPlanById.mockResolvedValue(mockPlan);

      const result = await billingService.checkLimit(testTenantId, 'users', 150);

      expect(result.has_access).toBe(false);
      expect(result.upgrade_required).toBe(true);
    });
  });

  // ==========================================================================
  // Usage Tests
  // ==========================================================================

  describe('getUsage', () => {
    it('should return usage metrics', async () => {
      mockedUsageService.getUsageSummary.mockResolvedValue({
        customer_id: testTenantId,
        period: '2026-01',
        mau: 50,
        api_calls: 5000,
        realms: 2,
        limits: { max_mau: 100, max_api_calls: 100000, max_realms: 5 },
        mau_percentage: 50,
        api_calls_percentage: 5,
        realms_percentage: 40,
        mau_warning: false,
        api_calls_warning: false,
        realms_warning: false,
        mau_exceeded: false,
        api_calls_exceeded: false,
        realms_exceeded: false
      });
      mockedSubscriptionRepo.getActiveSubscription.mockResolvedValue(mockSubscription);
      mockedBillingPlanRepo.getBillingPlanById.mockResolvedValue(mockPlan);

      const result = await billingService.getUsage(testTenantId);

      expect(result.tenant_id).toBe(testTenantId);
      expect(result.mau).toBe(50);
    });
  });

  // ==========================================================================
  // Webhook Tests
  // ==========================================================================

  describe('handleStripeWebhook', () => {
    it('should handle subscription.updated event', async () => {
      const stripeSubscription = {
        id: 'sub_stripe123',
        status: 'active',
        current_period_start: Math.floor(Date.now() / 1000),
        current_period_end: Math.floor(Date.now() / 1000) + 30 * 24 * 60 * 60,
        cancel_at_period_end: false
      };

      mockedSubscriptionRepo.getSubscriptionByStripeId.mockResolvedValue(mockSubscription);
      mockedSubscriptionRepo.updateSubscription.mockResolvedValue(mockSubscription);

      await billingService.handleStripeWebhook({
        type: 'customer.subscription.updated',
        data: { object: stripeSubscription }
      } as unknown as Stripe.Event);

      expect(mockedSubscriptionRepo.updateSubscription).toHaveBeenCalled();
    });

    it('should handle subscription.deleted event', async () => {
      mockedSubscriptionRepo.getSubscriptionByStripeId.mockResolvedValue(mockSubscription);
      mockedSubscriptionRepo.updateSubscription.mockResolvedValue({
        ...mockSubscription,
        status: 'canceled'
      });

      await billingService.handleStripeWebhook({
        type: 'customer.subscription.deleted',
        data: { object: { id: 'sub_stripe123' } }
      } as unknown as Stripe.Event);

      expect(mockedSubscriptionRepo.updateSubscription).toHaveBeenCalledWith(
        testTenantId,
        testSubscriptionId,
        expect.objectContaining({ status: 'canceled' })
      );
    });
  });

  describe('verifyWebhookSignature', () => {
    it('should verify valid webhook signature', () => {
      mockStripe.webhooks.constructEvent.mockReturnValue({
        type: 'test.event',
        data: { object: {} }
      });

      const result = billingService.verifyWebhookSignature('{}', 'sig');

      expect(result.type).toBe('test.event');
    });

    it('should throw error for invalid signature', () => {
      mockStripe.webhooks.constructEvent.mockImplementation(() => {
        throw new Error('Invalid signature');
      });

      expect(() => billingService.verifyWebhookSignature('{}', 'bad_sig'))
        .toThrow(BillingServiceError);
    });
  });
});
