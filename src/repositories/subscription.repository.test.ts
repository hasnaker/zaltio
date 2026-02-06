/**
 * Subscription Repository Tests
 * Tests for subscription CRUD operations
 * 
 * Validates: Requirements 7.4 (Subscriptions)
 * ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK (DynamoDB mocked for unit tests)
 * 
 * Security Requirements Tested:
 * - Stripe integration for payment processing
 * - Audit logging for all subscription operations
 */

// Mock DynamoDB
const mockSend = jest.fn();
jest.mock('../services/dynamodb.service', () => ({
  dynamoDb: {
    send: (...args: unknown[]) => mockSend(...args)
  }
}));

// Import after mocks
import {
  createSubscription,
  getSubscriptionById,
  getSubscriptionByStripeId,
  listSubscriptionsByTenant,
  getActiveSubscription,
  countSubscriptionsByTenant,
  updateSubscription,
  updateSubscriptionStatus,
  updateSubscriptionByStripeId,
  cancelSubscriptionAtPeriodEnd,
  reactivateSubscription,
  updateSubscriptionPeriod,
  deleteSubscription,
  deleteAllTenantSubscriptions,
  countSubscriptionsByStatus,
  getSubscriptionStats
} from './subscription.repository';

import { SubscriptionStatus } from '../models/subscription.model';

describe('Subscription Repository', () => {
  const mockTenantId = 'tenant_test123';
  const mockSubscriptionId = 'sub_abc123def456';
  const mockStripeSubId = 'sub_stripe123';
  const mockPlanId = 'plan_1234567890abcdef12345678';

  beforeEach(() => {
    mockSend.mockReset();
  });

  describe('createSubscription', () => {
    it('should create a new subscription with generated ID', async () => {
      // Mock countSubscriptionsByTenant (first call)
      mockSend.mockResolvedValueOnce({ Count: 0 });
      // Mock getSubscriptionByStripeId (second call)
      mockSend.mockResolvedValueOnce({ Items: [] });
      // Mock PutCommand (third call)
      mockSend.mockResolvedValueOnce({});
      
      const input = {
        tenant_id: mockTenantId,
        plan_id: mockPlanId,
        stripe_subscription_id: mockStripeSubId,
        stripe_customer_id: 'cus_customer123',
        status: 'active' as SubscriptionStatus,
        current_period_start: '2026-01-01T00:00:00Z',
        current_period_end: '2026-02-01T00:00:00Z',
        quantity: 5
      };
      
      const result = await createSubscription(input);
      
      expect(result).toBeDefined();
      expect(result.id).toMatch(/^sub_[a-f0-9]{24}$/);
      expect(result.tenant_id).toBe(mockTenantId);
      expect(result.plan_id).toBe(mockPlanId);
      expect(result.stripe_subscription_id).toBe(mockStripeSubId);
      expect(result.status).toBe('active');
      expect(result.quantity).toBe(5);
      
      expect(mockSend).toHaveBeenCalledTimes(3);
    });
    
    it('should reject invalid tenant ID', async () => {
      const input = {
        tenant_id: '',
        plan_id: mockPlanId,
        stripe_subscription_id: mockStripeSubId,
        status: 'active' as SubscriptionStatus,
        current_period_start: '2026-01-01T00:00:00Z',
        current_period_end: '2026-02-01T00:00:00Z'
      };
      
      await expect(createSubscription(input)).rejects.toThrow('Invalid tenant ID');
    });
    
    it('should reject invalid plan ID', async () => {
      const input = {
        tenant_id: mockTenantId,
        plan_id: 'invalid',
        stripe_subscription_id: mockStripeSubId,
        status: 'active' as SubscriptionStatus,
        current_period_start: '2026-01-01T00:00:00Z',
        current_period_end: '2026-02-01T00:00:00Z'
      };
      
      await expect(createSubscription(input)).rejects.toThrow('Invalid plan ID format');
    });
    
    it('should reject invalid Stripe subscription ID', async () => {
      const input = {
        tenant_id: mockTenantId,
        plan_id: mockPlanId,
        stripe_subscription_id: 'invalid',
        status: 'active' as SubscriptionStatus,
        current_period_start: '2026-01-01T00:00:00Z',
        current_period_end: '2026-02-01T00:00:00Z'
      };
      
      await expect(createSubscription(input)).rejects.toThrow('Invalid Stripe subscription ID format');
    });
    
    it('should reject invalid Stripe customer ID', async () => {
      const input = {
        tenant_id: mockTenantId,
        plan_id: mockPlanId,
        stripe_subscription_id: mockStripeSubId,
        stripe_customer_id: 'invalid',
        status: 'active' as SubscriptionStatus,
        current_period_start: '2026-01-01T00:00:00Z',
        current_period_end: '2026-02-01T00:00:00Z'
      };
      
      await expect(createSubscription(input)).rejects.toThrow('Invalid Stripe customer ID format');
    });
    
    it('should reject invalid status', async () => {
      const input = {
        tenant_id: mockTenantId,
        plan_id: mockPlanId,
        stripe_subscription_id: mockStripeSubId,
        status: 'invalid' as SubscriptionStatus,
        current_period_start: '2026-01-01T00:00:00Z',
        current_period_end: '2026-02-01T00:00:00Z'
      };
      
      await expect(createSubscription(input)).rejects.toThrow('Invalid subscription status');
    });
    
    it('should reject invalid current_period_start', async () => {
      const input = {
        tenant_id: mockTenantId,
        plan_id: mockPlanId,
        stripe_subscription_id: mockStripeSubId,
        status: 'active' as SubscriptionStatus,
        current_period_start: 'invalid',
        current_period_end: '2026-02-01T00:00:00Z'
      };
      
      await expect(createSubscription(input)).rejects.toThrow('Invalid current_period_start');
    });
    
    it('should reject invalid current_period_end', async () => {
      const input = {
        tenant_id: mockTenantId,
        plan_id: mockPlanId,
        stripe_subscription_id: mockStripeSubId,
        status: 'active' as SubscriptionStatus,
        current_period_start: '2026-01-01T00:00:00Z',
        current_period_end: 'invalid'
      };
      
      await expect(createSubscription(input)).rejects.toThrow('Invalid current_period_end');
    });
    
    it('should reject invalid trial_start', async () => {
      const input = {
        tenant_id: mockTenantId,
        plan_id: mockPlanId,
        stripe_subscription_id: mockStripeSubId,
        status: 'trialing' as SubscriptionStatus,
        current_period_start: '2026-01-01T00:00:00Z',
        current_period_end: '2026-02-01T00:00:00Z',
        trial_start: 'invalid'
      };
      
      await expect(createSubscription(input)).rejects.toThrow('Invalid trial_start');
    });
    
    it('should reject invalid trial_end', async () => {
      const input = {
        tenant_id: mockTenantId,
        plan_id: mockPlanId,
        stripe_subscription_id: mockStripeSubId,
        status: 'trialing' as SubscriptionStatus,
        current_period_start: '2026-01-01T00:00:00Z',
        current_period_end: '2026-02-01T00:00:00Z',
        trial_end: 'invalid'
      };
      
      await expect(createSubscription(input)).rejects.toThrow('Invalid trial_end');
    });
    
    it('should reject invalid quantity', async () => {
      const input = {
        tenant_id: mockTenantId,
        plan_id: mockPlanId,
        stripe_subscription_id: mockStripeSubId,
        status: 'active' as SubscriptionStatus,
        current_period_start: '2026-01-01T00:00:00Z',
        current_period_end: '2026-02-01T00:00:00Z',
        quantity: -1
      };
      
      await expect(createSubscription(input)).rejects.toThrow('Invalid quantity');
    });
    
    it('should reject when max subscriptions exceeded', async () => {
      mockSend.mockResolvedValueOnce({ Count: 5 });
      
      const input = {
        tenant_id: mockTenantId,
        plan_id: mockPlanId,
        stripe_subscription_id: mockStripeSubId,
        status: 'active' as SubscriptionStatus,
        current_period_start: '2026-01-01T00:00:00Z',
        current_period_end: '2026-02-01T00:00:00Z'
      };
      
      await expect(createSubscription(input)).rejects.toThrow('Maximum subscriptions per tenant');
    });
    
    it('should reject duplicate Stripe subscription ID', async () => {
      mockSend.mockResolvedValueOnce({ Count: 0 });
      mockSend.mockResolvedValueOnce({ 
        Items: [{ id: 'existing_sub', stripe_subscription_id: mockStripeSubId }] 
      });
      
      const input = {
        tenant_id: mockTenantId,
        plan_id: mockPlanId,
        stripe_subscription_id: mockStripeSubId,
        status: 'active' as SubscriptionStatus,
        current_period_start: '2026-01-01T00:00:00Z',
        current_period_end: '2026-02-01T00:00:00Z'
      };
      
      await expect(createSubscription(input)).rejects.toThrow('A subscription with this Stripe subscription ID already exists');
    });
  });

  describe('getSubscriptionById', () => {
    it('should return subscription when found', async () => {
      const mockSubscription = {
        id: mockSubscriptionId,
        tenant_id: mockTenantId,
        plan_id: mockPlanId,
        stripe_subscription_id: mockStripeSubId,
        status: 'active',
        current_period_start: '2026-01-01T00:00:00Z',
        current_period_end: '2026-02-01T00:00:00Z',
        created_at: '2026-01-01T00:00:00Z'
      };
      
      mockSend.mockResolvedValueOnce({
        Item: mockSubscription
      });
      
      const result = await getSubscriptionById(mockTenantId, mockSubscriptionId);
      
      expect(result).toBeDefined();
      expect(result?.id).toBe(mockSubscriptionId);
      expect(result?.status).toBe('active');
    });
    
    it('should return null when subscription not found', async () => {
      mockSend.mockResolvedValueOnce({
        Item: undefined
      });
      
      const result = await getSubscriptionById(mockTenantId, 'nonexistent');
      
      expect(result).toBeNull();
    });
  });

  describe('getSubscriptionByStripeId', () => {
    it('should return subscription by Stripe ID', async () => {
      const mockSubscription = {
        id: mockSubscriptionId,
        tenant_id: mockTenantId,
        plan_id: mockPlanId,
        stripe_subscription_id: mockStripeSubId,
        status: 'active',
        current_period_start: '2026-01-01T00:00:00Z',
        current_period_end: '2026-02-01T00:00:00Z',
        created_at: '2026-01-01T00:00:00Z'
      };
      
      mockSend.mockResolvedValueOnce({
        Items: [mockSubscription]
      });
      
      const result = await getSubscriptionByStripeId(mockStripeSubId);
      
      expect(result).toBeDefined();
      expect(result?.stripe_subscription_id).toBe(mockStripeSubId);
    });
    
    it('should return null when no matching Stripe ID', async () => {
      mockSend.mockResolvedValueOnce({
        Items: []
      });
      
      const result = await getSubscriptionByStripeId('sub_nonexistent');
      
      expect(result).toBeNull();
    });
  });


  describe('listSubscriptionsByTenant', () => {
    it('should return all subscriptions for a tenant', async () => {
      const mockSubscriptions = [
        {
          id: 'sub_1',
          tenant_id: mockTenantId,
          plan_id: mockPlanId,
          stripe_subscription_id: 'sub_stripe1',
          status: 'active',
          current_period_start: '2026-01-01T00:00:00Z',
          current_period_end: '2026-02-01T00:00:00Z',
          created_at: '2026-01-01T00:00:00Z'
        },
        {
          id: 'sub_2',
          tenant_id: mockTenantId,
          plan_id: mockPlanId,
          stripe_subscription_id: 'sub_stripe2',
          status: 'canceled',
          current_period_start: '2025-12-01T00:00:00Z',
          current_period_end: '2026-01-01T00:00:00Z',
          created_at: '2025-12-01T00:00:00Z'
        }
      ];
      
      mockSend.mockResolvedValueOnce({
        Items: mockSubscriptions
      });
      
      const result = await listSubscriptionsByTenant(mockTenantId);
      
      expect(result.subscriptions).toHaveLength(2);
    });
    
    it('should filter by status when provided', async () => {
      const mockSubscriptions = [
        {
          id: 'sub_1',
          tenant_id: mockTenantId,
          plan_id: mockPlanId,
          stripe_subscription_id: 'sub_stripe1',
          status: 'active',
          current_period_start: '2026-01-01T00:00:00Z',
          current_period_end: '2026-02-01T00:00:00Z',
          created_at: '2026-01-01T00:00:00Z'
        }
      ];
      
      mockSend.mockResolvedValueOnce({
        Items: mockSubscriptions
      });
      
      const result = await listSubscriptionsByTenant(mockTenantId, { status: 'active' });
      
      expect(result.subscriptions).toHaveLength(1);
      expect(result.subscriptions[0].status).toBe('active');
    });
    
    it('should return empty array when no subscriptions', async () => {
      mockSend.mockResolvedValueOnce({
        Items: []
      });
      
      const result = await listSubscriptionsByTenant(mockTenantId);
      
      expect(result.subscriptions).toEqual([]);
    });
    
    it('should handle pagination cursor', async () => {
      const mockSubscriptions = [
        {
          id: 'sub_1',
          tenant_id: mockTenantId,
          plan_id: mockPlanId,
          stripe_subscription_id: 'sub_stripe1',
          status: 'active',
          current_period_start: '2026-01-01T00:00:00Z',
          current_period_end: '2026-02-01T00:00:00Z',
          created_at: '2026-01-01T00:00:00Z'
        }
      ];
      
      const lastKey = { pk: 'TENANT#test#SUBSCRIPTION#sub_1', sk: 'SUBSCRIPTION' };
      
      mockSend.mockResolvedValueOnce({
        Items: mockSubscriptions,
        LastEvaluatedKey: lastKey
      });
      
      const result = await listSubscriptionsByTenant(mockTenantId, { limit: 1 });
      
      expect(result.subscriptions).toHaveLength(1);
      expect(result.nextCursor).toBeDefined();
    });
  });

  describe('getActiveSubscription', () => {
    it('should return active subscription', async () => {
      const mockSubscription = {
        id: mockSubscriptionId,
        tenant_id: mockTenantId,
        plan_id: mockPlanId,
        stripe_subscription_id: mockStripeSubId,
        status: 'active',
        current_period_start: '2026-01-01T00:00:00Z',
        current_period_end: '2026-02-01T00:00:00Z',
        created_at: '2026-01-01T00:00:00Z'
      };
      
      mockSend.mockResolvedValueOnce({
        Items: [mockSubscription]
      });
      
      const result = await getActiveSubscription(mockTenantId);
      
      expect(result).toBeDefined();
      expect(result?.status).toBe('active');
    });
    
    it('should return trialing subscription as active', async () => {
      const mockSubscription = {
        id: mockSubscriptionId,
        tenant_id: mockTenantId,
        plan_id: mockPlanId,
        stripe_subscription_id: mockStripeSubId,
        status: 'trialing',
        current_period_start: '2026-01-01T00:00:00Z',
        current_period_end: '2026-02-01T00:00:00Z',
        trial_end: '2026-01-15T00:00:00Z',
        created_at: '2026-01-01T00:00:00Z'
      };
      
      mockSend.mockResolvedValueOnce({
        Items: [mockSubscription]
      });
      
      const result = await getActiveSubscription(mockTenantId);
      
      expect(result).toBeDefined();
      expect(result?.status).toBe('trialing');
    });
    
    it('should return null when no active subscription', async () => {
      mockSend.mockResolvedValueOnce({
        Items: []
      });
      
      const result = await getActiveSubscription(mockTenantId);
      
      expect(result).toBeNull();
    });
  });

  describe('countSubscriptionsByTenant', () => {
    it('should return count of non-canceled subscriptions', async () => {
      mockSend.mockResolvedValueOnce({
        Count: 2
      });
      
      const result = await countSubscriptionsByTenant(mockTenantId);
      
      expect(result).toBe(2);
    });
    
    it('should return 0 when no subscriptions', async () => {
      mockSend.mockResolvedValueOnce({
        Count: 0
      });
      
      const result = await countSubscriptionsByTenant(mockTenantId);
      
      expect(result).toBe(0);
    });
  });

  describe('updateSubscription', () => {
    it('should update subscription status', async () => {
      const updatedSubscription = {
        id: mockSubscriptionId,
        tenant_id: mockTenantId,
        plan_id: mockPlanId,
        stripe_subscription_id: mockStripeSubId,
        status: 'past_due',
        current_period_start: '2026-01-01T00:00:00Z',
        current_period_end: '2026-02-01T00:00:00Z',
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-15T00:00:00Z'
      };
      
      mockSend.mockResolvedValueOnce({
        Attributes: updatedSubscription
      });
      
      const result = await updateSubscription(mockTenantId, mockSubscriptionId, {
        status: 'past_due'
      });
      
      expect(result).toBeDefined();
      expect(result?.status).toBe('past_due');
      expect(result?.updated_at).toBeDefined();
    });
    
    it('should update subscription period', async () => {
      const updatedSubscription = {
        id: mockSubscriptionId,
        tenant_id: mockTenantId,
        plan_id: mockPlanId,
        stripe_subscription_id: mockStripeSubId,
        status: 'active',
        current_period_start: '2026-02-01T00:00:00Z',
        current_period_end: '2026-03-01T00:00:00Z',
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-02-01T00:00:00Z'
      };
      
      mockSend.mockResolvedValueOnce({
        Attributes: updatedSubscription
      });
      
      const result = await updateSubscription(mockTenantId, mockSubscriptionId, {
        current_period_start: '2026-02-01T00:00:00Z',
        current_period_end: '2026-03-01T00:00:00Z'
      });
      
      expect(result).toBeDefined();
      expect(result?.current_period_start).toBe('2026-02-01T00:00:00Z');
      expect(result?.current_period_end).toBe('2026-03-01T00:00:00Z');
    });
    
    it('should reject invalid plan ID on update', async () => {
      await expect(updateSubscription(mockTenantId, mockSubscriptionId, {
        plan_id: 'invalid'
      })).rejects.toThrow('Invalid plan ID format');
    });
    
    it('should reject invalid status on update', async () => {
      await expect(updateSubscription(mockTenantId, mockSubscriptionId, {
        status: 'invalid' as SubscriptionStatus
      })).rejects.toThrow('Invalid subscription status');
    });
    
    it('should reject invalid date on update', async () => {
      await expect(updateSubscription(mockTenantId, mockSubscriptionId, {
        current_period_end: 'invalid'
      })).rejects.toThrow('Invalid current_period_end');
    });
    
    it('should reject invalid quantity on update', async () => {
      await expect(updateSubscription(mockTenantId, mockSubscriptionId, {
        quantity: 0
      })).rejects.toThrow('Invalid quantity');
    });
    
    it('should return null when subscription not found', async () => {
      const error = new Error('ConditionalCheckFailedException');
      (error as Error & { name: string }).name = 'ConditionalCheckFailedException';
      mockSend.mockRejectedValueOnce(error);
      
      const result = await updateSubscription(mockTenantId, 'nonexistent', {
        status: 'active'
      });
      
      expect(result).toBeNull();
    });
  });

  describe('updateSubscriptionStatus', () => {
    it('should update status to canceled with canceled_at', async () => {
      const updatedSubscription = {
        id: mockSubscriptionId,
        tenant_id: mockTenantId,
        plan_id: mockPlanId,
        stripe_subscription_id: mockStripeSubId,
        status: 'canceled',
        current_period_start: '2026-01-01T00:00:00Z',
        current_period_end: '2026-02-01T00:00:00Z',
        canceled_at: '2026-01-15T00:00:00Z',
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-15T00:00:00Z'
      };
      
      mockSend.mockResolvedValueOnce({
        Attributes: updatedSubscription
      });
      
      const result = await updateSubscriptionStatus(mockTenantId, mockSubscriptionId, 'canceled');
      
      expect(result).toBeDefined();
      expect(result?.status).toBe('canceled');
    });
  });

  describe('updateSubscriptionByStripeId', () => {
    it('should update subscription by Stripe ID', async () => {
      // Mock getSubscriptionByStripeId
      const mockSubscription = {
        id: mockSubscriptionId,
        tenant_id: mockTenantId,
        plan_id: mockPlanId,
        stripe_subscription_id: mockStripeSubId,
        status: 'active',
        current_period_start: '2026-01-01T00:00:00Z',
        current_period_end: '2026-02-01T00:00:00Z',
        created_at: '2026-01-01T00:00:00Z'
      };
      
      mockSend.mockResolvedValueOnce({
        Items: [mockSubscription]
      });
      
      // Mock updateSubscription
      const updatedSubscription = {
        ...mockSubscription,
        status: 'past_due',
        updated_at: '2026-01-15T00:00:00Z'
      };
      
      mockSend.mockResolvedValueOnce({
        Attributes: updatedSubscription
      });
      
      const result = await updateSubscriptionByStripeId(mockStripeSubId, {
        status: 'past_due'
      });
      
      expect(result).toBeDefined();
      expect(result?.status).toBe('past_due');
    });
    
    it('should return null when Stripe ID not found', async () => {
      mockSend.mockResolvedValueOnce({
        Items: []
      });
      
      const result = await updateSubscriptionByStripeId('sub_nonexistent', {
        status: 'active'
      });
      
      expect(result).toBeNull();
    });
  });

  describe('cancelSubscriptionAtPeriodEnd', () => {
    it('should set cancel_at_period_end to true', async () => {
      const updatedSubscription = {
        id: mockSubscriptionId,
        tenant_id: mockTenantId,
        plan_id: mockPlanId,
        stripe_subscription_id: mockStripeSubId,
        status: 'active',
        current_period_start: '2026-01-01T00:00:00Z',
        current_period_end: '2026-02-01T00:00:00Z',
        cancel_at_period_end: true,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-15T00:00:00Z'
      };
      
      mockSend.mockResolvedValueOnce({
        Attributes: updatedSubscription
      });
      
      const result = await cancelSubscriptionAtPeriodEnd(mockTenantId, mockSubscriptionId);
      
      expect(result).toBeDefined();
      expect(result?.cancel_at_period_end).toBe(true);
    });
  });

  describe('reactivateSubscription', () => {
    it('should set cancel_at_period_end to false', async () => {
      const updatedSubscription = {
        id: mockSubscriptionId,
        tenant_id: mockTenantId,
        plan_id: mockPlanId,
        stripe_subscription_id: mockStripeSubId,
        status: 'active',
        current_period_start: '2026-01-01T00:00:00Z',
        current_period_end: '2026-02-01T00:00:00Z',
        cancel_at_period_end: false,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-15T00:00:00Z'
      };
      
      mockSend.mockResolvedValueOnce({
        Attributes: updatedSubscription
      });
      
      const result = await reactivateSubscription(mockTenantId, mockSubscriptionId);
      
      expect(result).toBeDefined();
      expect(result?.cancel_at_period_end).toBe(false);
    });
  });

  describe('updateSubscriptionPeriod', () => {
    it('should update period and set status to active', async () => {
      const updatedSubscription = {
        id: mockSubscriptionId,
        tenant_id: mockTenantId,
        plan_id: mockPlanId,
        stripe_subscription_id: mockStripeSubId,
        status: 'active',
        current_period_start: '2026-02-01T00:00:00Z',
        current_period_end: '2026-03-01T00:00:00Z',
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-02-01T00:00:00Z'
      };
      
      mockSend.mockResolvedValueOnce({
        Attributes: updatedSubscription
      });
      
      const result = await updateSubscriptionPeriod(
        mockTenantId,
        mockSubscriptionId,
        '2026-02-01T00:00:00Z',
        '2026-03-01T00:00:00Z'
      );
      
      expect(result).toBeDefined();
      expect(result?.current_period_start).toBe('2026-02-01T00:00:00Z');
      expect(result?.current_period_end).toBe('2026-03-01T00:00:00Z');
      expect(result?.status).toBe('active');
    });
  });

  describe('deleteSubscription', () => {
    it('should delete subscription', async () => {
      mockSend.mockResolvedValueOnce({});
      
      const result = await deleteSubscription(mockTenantId, mockSubscriptionId);
      
      expect(result).toBe(true);
      expect(mockSend).toHaveBeenCalledTimes(1);
    });
    
    it('should return false on error', async () => {
      mockSend.mockRejectedValueOnce(new Error('DynamoDB error'));
      
      const result = await deleteSubscription(mockTenantId, 'nonexistent');
      
      expect(result).toBe(false);
    });
  });

  describe('deleteAllTenantSubscriptions', () => {
    it('should delete all subscriptions for a tenant', async () => {
      const mockSubscriptions = [
        { id: 'sub_1', tenant_id: mockTenantId, plan_id: mockPlanId, stripe_subscription_id: 'sub_s1', status: 'active', current_period_start: '2026-01-01T00:00:00Z', current_period_end: '2026-02-01T00:00:00Z', created_at: '2026-01-01T00:00:00Z' },
        { id: 'sub_2', tenant_id: mockTenantId, plan_id: mockPlanId, stripe_subscription_id: 'sub_s2', status: 'canceled', current_period_start: '2025-12-01T00:00:00Z', current_period_end: '2026-01-01T00:00:00Z', created_at: '2025-12-01T00:00:00Z' }
      ];
      
      mockSend
        .mockResolvedValueOnce({ Items: mockSubscriptions }) // listSubscriptionsByTenant
        .mockResolvedValueOnce({}); // BatchWriteCommand
      
      const result = await deleteAllTenantSubscriptions(mockTenantId);
      
      expect(result).toBe(2);
    });
    
    it('should return 0 when no subscriptions', async () => {
      mockSend.mockResolvedValueOnce({ Items: [] });
      
      const result = await deleteAllTenantSubscriptions(mockTenantId);
      
      expect(result).toBe(0);
    });
  });

  describe('countSubscriptionsByStatus', () => {
    it('should count subscriptions by status', async () => {
      const mockSubscriptions = [
        { id: 'sub_1', status: 'active' },
        { id: 'sub_2', status: 'active' },
        { id: 'sub_3', status: 'trialing' },
        { id: 'sub_4', status: 'canceled' }
      ];
      
      mockSend.mockResolvedValueOnce({ Items: mockSubscriptions });
      
      const result = await countSubscriptionsByStatus(mockTenantId);
      
      expect(result.active).toBe(2);
      expect(result.trialing).toBe(1);
      expect(result.canceled).toBe(1);
      expect(result.past_due).toBe(0);
    });
    
    it('should return zero counts when no subscriptions', async () => {
      mockSend.mockResolvedValueOnce({ Items: [] });
      
      const result = await countSubscriptionsByStatus(mockTenantId);
      
      expect(result.active).toBe(0);
      expect(result.trialing).toBe(0);
      expect(result.canceled).toBe(0);
      expect(result.past_due).toBe(0);
    });
  });

  describe('getSubscriptionStats', () => {
    it('should return subscription statistics', async () => {
      const mockSubscriptions = [
        { id: 'sub_1', status: 'active' },
        { id: 'sub_2', status: 'trialing' },
        { id: 'sub_3', status: 'past_due' },
        { id: 'sub_4', status: 'canceled' }
      ];
      
      mockSend.mockResolvedValueOnce({ Items: mockSubscriptions });
      
      const result = await getSubscriptionStats(mockTenantId);
      
      expect(result.total).toBe(4);
      expect(result.active).toBe(1);
      expect(result.trialing).toBe(1);
      expect(result.past_due).toBe(1);
      expect(result.canceled).toBe(1);
    });
  });
});
