/**
 * BillingPlan Repository Tests
 * Tests for billing plan CRUD operations
 * 
 * Validates: Requirements 7.2 (Billing Plans)
 * ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK (DynamoDB mocked for unit tests)
 * 
 * Security Requirements Tested:
 * - Stripe integration for payment processing
 * - Audit logging for all billing operations
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
  createBillingPlan,
  getBillingPlanById,
  listBillingPlansByRealm,
  getActiveBillingPlans,
  getDefaultBillingPlan,
  countBillingPlansByRealm,
  getBillingPlanByStripePriceId,
  updateBillingPlan,
  updateBillingPlanStatus,
  setDefaultBillingPlan,
  archiveBillingPlan,
  hardDeleteBillingPlan,
  deleteAllRealmBillingPlans,
  countBillingPlansByStatus
} from './billing-plan.repository';

import {
  BillingPlanType,
  BillingPlanStatus
} from '../models/billing-plan.model';

describe('BillingPlan Repository', () => {
  const mockRealmId = 'realm_test123';
  const mockPlanId = 'plan_abc123def456';

  beforeEach(() => {
    mockSend.mockReset();
  });

  describe('createBillingPlan', () => {
    it('should create a new billing plan with generated ID', async () => {
      // Mock countBillingPlansByRealm (first call)
      mockSend.mockResolvedValueOnce({ Count: 0 });
      // Mock PutCommand (second call)
      mockSend.mockResolvedValueOnce({});
      
      const input = {
        realm_id: mockRealmId,
        name: 'Pro Plan',
        description: 'Professional tier',
        type: 'per_user' as BillingPlanType,
        price_monthly: 999,
        price_yearly: 9990,
        currency: 'usd',
        features: ['sso', 'api_access'],
        limits: { users: 10, storage_gb: 100 },
        stripe_price_id_monthly: 'price_monthly123',
        stripe_price_id_yearly: 'price_yearly123',
        stripe_product_id: 'prod_123',
        trial_days: 14,
        sort_order: 1
      };
      
      const result = await createBillingPlan(input);
      
      expect(result).toBeDefined();
      expect(result.id).toMatch(/^plan_[a-f0-9]{24}$/);
      expect(result.realm_id).toBe(mockRealmId);
      expect(result.name).toBe('Pro Plan');
      expect(result.type).toBe('per_user');
      expect(result.price_monthly).toBe(999);
      expect(result.price_yearly).toBe(9990);
      expect(result.currency).toBe('usd');
      expect(result.features).toEqual(['sso', 'api_access']);
      expect(result.limits).toEqual({ users: 10, storage_gb: 100 });
      expect(result.status).toBe('active');
      expect(result.trial_days).toBe(14);
      
      expect(mockSend).toHaveBeenCalledTimes(2);
    });
    
    it('should reject invalid plan name', async () => {
      const input = {
        realm_id: mockRealmId,
        name: '',
        type: 'per_user' as BillingPlanType,
        price_monthly: 999,
        price_yearly: 9990,
        features: [],
        limits: {}
      };
      
      await expect(createBillingPlan(input)).rejects.toThrow('Invalid plan name');
    });
    
    it('should reject invalid plan type', async () => {
      const input = {
        realm_id: mockRealmId,
        name: 'Test Plan',
        type: 'invalid' as BillingPlanType,
        price_monthly: 999,
        price_yearly: 9990,
        features: [],
        limits: {}
      };
      
      await expect(createBillingPlan(input)).rejects.toThrow('Invalid billing plan type');
    });
    
    it('should reject invalid monthly price', async () => {
      const input = {
        realm_id: mockRealmId,
        name: 'Test Plan',
        type: 'per_user' as BillingPlanType,
        price_monthly: -100,
        price_yearly: 9990,
        features: [],
        limits: {}
      };
      
      await expect(createBillingPlan(input)).rejects.toThrow('Invalid monthly price');
    });
    
    it('should reject invalid yearly price', async () => {
      const input = {
        realm_id: mockRealmId,
        name: 'Test Plan',
        type: 'per_user' as BillingPlanType,
        price_monthly: 999,
        price_yearly: -100,
        features: [],
        limits: {}
      };
      
      await expect(createBillingPlan(input)).rejects.toThrow('Invalid yearly price');
    });
    
    it('should reject invalid currency', async () => {
      const input = {
        realm_id: mockRealmId,
        name: 'Test Plan',
        type: 'per_user' as BillingPlanType,
        price_monthly: 999,
        price_yearly: 9990,
        currency: 'invalid',
        features: [],
        limits: {}
      };
      
      await expect(createBillingPlan(input)).rejects.toThrow('Invalid currency');
    });
    
    it('should reject invalid features', async () => {
      const input = {
        realm_id: mockRealmId,
        name: 'Test Plan',
        type: 'per_user' as BillingPlanType,
        price_monthly: 999,
        price_yearly: 9990,
        features: [''],
        limits: {}
      };
      
      await expect(createBillingPlan(input)).rejects.toThrow('Invalid features');
    });
    
    it('should reject invalid limits', async () => {
      const input = {
        realm_id: mockRealmId,
        name: 'Test Plan',
        type: 'per_user' as BillingPlanType,
        price_monthly: 999,
        price_yearly: 9990,
        features: [],
        limits: { users: -1 }
      };
      
      await expect(createBillingPlan(input)).rejects.toThrow('Invalid limits');
    });
    
    it('should reject invalid Stripe monthly price ID', async () => {
      mockSend.mockResolvedValueOnce({ Count: 0 });
      
      const input = {
        realm_id: mockRealmId,
        name: 'Test Plan',
        type: 'per_user' as BillingPlanType,
        price_monthly: 999,
        price_yearly: 9990,
        features: [],
        limits: {},
        stripe_price_id_monthly: 'invalid'
      };
      
      await expect(createBillingPlan(input)).rejects.toThrow('Invalid Stripe monthly price ID');
    });
    
    it('should reject invalid Stripe yearly price ID', async () => {
      mockSend.mockResolvedValueOnce({ Count: 0 });
      
      const input = {
        realm_id: mockRealmId,
        name: 'Test Plan',
        type: 'per_user' as BillingPlanType,
        price_monthly: 999,
        price_yearly: 9990,
        features: [],
        limits: {},
        stripe_price_id_yearly: 'invalid'
      };
      
      await expect(createBillingPlan(input)).rejects.toThrow('Invalid Stripe yearly price ID');
    });
    
    it('should reject invalid Stripe product ID', async () => {
      mockSend.mockResolvedValueOnce({ Count: 0 });
      
      const input = {
        realm_id: mockRealmId,
        name: 'Test Plan',
        type: 'per_user' as BillingPlanType,
        price_monthly: 999,
        price_yearly: 9990,
        features: [],
        limits: {},
        stripe_product_id: 'invalid'
      };
      
      await expect(createBillingPlan(input)).rejects.toThrow('Invalid Stripe product ID');
    });
    
    it('should reject when max plans exceeded', async () => {
      mockSend.mockResolvedValueOnce({ Count: 20 });
      
      const input = {
        realm_id: mockRealmId,
        name: 'Test Plan',
        type: 'per_user' as BillingPlanType,
        price_monthly: 999,
        price_yearly: 9990,
        features: [],
        limits: {}
      };
      
      await expect(createBillingPlan(input)).rejects.toThrow('Maximum billing plans per realm');
    });
    
    it('should use default currency when not provided', async () => {
      mockSend.mockResolvedValueOnce({ Count: 0 });
      mockSend.mockResolvedValueOnce({});
      
      const input = {
        realm_id: mockRealmId,
        name: 'Test Plan',
        type: 'per_user' as BillingPlanType,
        price_monthly: 999,
        price_yearly: 9990,
        features: [],
        limits: {}
      };
      
      const result = await createBillingPlan(input);
      
      expect(result.currency).toBe('usd');
    });
  });

  describe('getBillingPlanById', () => {
    it('should return billing plan when found', async () => {
      const mockPlan = {
        id: mockPlanId,
        realm_id: mockRealmId,
        name: 'Pro Plan',
        type: 'per_user',
        price_monthly: 999,
        price_yearly: 9990,
        currency: 'usd',
        features: ['sso'],
        limits: { users: 10 },
        status: 'active',
        created_at: '2026-01-25T10:00:00Z'
      };
      
      mockSend.mockResolvedValueOnce({
        Item: mockPlan
      });
      
      const result = await getBillingPlanById(mockRealmId, mockPlanId);
      
      expect(result).toBeDefined();
      expect(result?.id).toBe(mockPlanId);
      expect(result?.name).toBe('Pro Plan');
      expect(result?.status).toBe('active');
    });
    
    it('should return null when billing plan not found', async () => {
      mockSend.mockResolvedValueOnce({
        Item: undefined
      });
      
      const result = await getBillingPlanById(mockRealmId, 'nonexistent');
      
      expect(result).toBeNull();
    });
  });

  describe('listBillingPlansByRealm', () => {
    it('should return all billing plans for a realm', async () => {
      const mockPlans = [
        {
          id: 'plan_1',
          realm_id: mockRealmId,
          name: 'Basic',
          type: 'flat_rate',
          price_monthly: 0,
          price_yearly: 0,
          currency: 'usd',
          features: [],
          limits: {},
          status: 'active',
          sort_order: 1,
          created_at: '2026-01-25T10:00:00Z'
        },
        {
          id: 'plan_2',
          realm_id: mockRealmId,
          name: 'Pro',
          type: 'per_user',
          price_monthly: 999,
          price_yearly: 9990,
          currency: 'usd',
          features: ['sso'],
          limits: { users: 10 },
          status: 'active',
          sort_order: 2,
          created_at: '2026-01-26T10:00:00Z'
        }
      ];
      
      mockSend.mockResolvedValueOnce({
        Items: mockPlans
      });
      
      const result = await listBillingPlansByRealm(mockRealmId);
      
      expect(result.plans).toHaveLength(2);
      expect(result.plans[0].name).toBe('Basic');
      expect(result.plans[1].name).toBe('Pro');
    });
    
    it('should filter by status when provided', async () => {
      const mockPlans = [
        {
          id: 'plan_1',
          realm_id: mockRealmId,
          name: 'Active Plan',
          type: 'flat_rate',
          price_monthly: 0,
          price_yearly: 0,
          currency: 'usd',
          features: [],
          limits: {},
          status: 'active',
          created_at: '2026-01-25T10:00:00Z'
        }
      ];
      
      mockSend.mockResolvedValueOnce({
        Items: mockPlans
      });
      
      const result = await listBillingPlansByRealm(mockRealmId, { status: 'active' });
      
      expect(result.plans).toHaveLength(1);
      expect(result.plans[0].status).toBe('active');
    });
    
    it('should return empty array when no plans', async () => {
      mockSend.mockResolvedValueOnce({
        Items: []
      });
      
      const result = await listBillingPlansByRealm(mockRealmId);
      
      expect(result.plans).toEqual([]);
    });
    
    it('should handle pagination cursor', async () => {
      const mockPlans = [
        {
          id: 'plan_1',
          realm_id: mockRealmId,
          name: 'Plan 1',
          type: 'flat_rate',
          price_monthly: 0,
          price_yearly: 0,
          currency: 'usd',
          features: [],
          limits: {},
          status: 'active',
          created_at: '2026-01-25T10:00:00Z'
        }
      ];
      
      const lastKey = { pk: 'REALM#test#PLAN#plan_1', sk: 'PLAN' };
      
      mockSend.mockResolvedValueOnce({
        Items: mockPlans,
        LastEvaluatedKey: lastKey
      });
      
      const result = await listBillingPlansByRealm(mockRealmId, { limit: 1 });
      
      expect(result.plans).toHaveLength(1);
      expect(result.nextCursor).toBeDefined();
    });
    
    it('should sort by sort_order when requested', async () => {
      const mockPlans = [
        {
          id: 'plan_2',
          realm_id: mockRealmId,
          name: 'Pro',
          type: 'per_user',
          price_monthly: 999,
          price_yearly: 9990,
          currency: 'usd',
          features: [],
          limits: {},
          status: 'active',
          sort_order: 2,
          created_at: '2026-01-26T10:00:00Z'
        },
        {
          id: 'plan_1',
          realm_id: mockRealmId,
          name: 'Basic',
          type: 'flat_rate',
          price_monthly: 0,
          price_yearly: 0,
          currency: 'usd',
          features: [],
          limits: {},
          status: 'active',
          sort_order: 1,
          created_at: '2026-01-25T10:00:00Z'
        }
      ];
      
      mockSend.mockResolvedValueOnce({
        Items: mockPlans
      });
      
      const result = await listBillingPlansByRealm(mockRealmId, { sortByOrder: true });
      
      expect(result.plans[0].name).toBe('Basic');
      expect(result.plans[1].name).toBe('Pro');
    });
  });

  describe('getActiveBillingPlans', () => {
    it('should return only active plans sorted by order', async () => {
      const mockPlans = [
        {
          id: 'plan_2',
          realm_id: mockRealmId,
          name: 'Pro',
          type: 'per_user',
          price_monthly: 999,
          price_yearly: 9990,
          currency: 'usd',
          features: [],
          limits: {},
          status: 'active',
          sort_order: 2,
          created_at: '2026-01-26T10:00:00Z'
        },
        {
          id: 'plan_1',
          realm_id: mockRealmId,
          name: 'Basic',
          type: 'flat_rate',
          price_monthly: 0,
          price_yearly: 0,
          currency: 'usd',
          features: [],
          limits: {},
          status: 'active',
          sort_order: 1,
          created_at: '2026-01-25T10:00:00Z'
        }
      ];
      
      mockSend.mockResolvedValueOnce({
        Items: mockPlans
      });
      
      const result = await getActiveBillingPlans(mockRealmId);
      
      expect(result).toHaveLength(2);
      expect(result[0].name).toBe('Basic');
      expect(result[1].name).toBe('Pro');
    });
  });

  describe('getDefaultBillingPlan', () => {
    it('should return default plan when exists', async () => {
      const mockPlan = {
        id: 'plan_default',
        realm_id: mockRealmId,
        name: 'Free',
        type: 'flat_rate',
        price_monthly: 0,
        price_yearly: 0,
        currency: 'usd',
        features: [],
        limits: {},
        status: 'active',
        is_default: true,
        created_at: '2026-01-25T10:00:00Z'
      };
      
      mockSend.mockResolvedValueOnce({
        Items: [mockPlan]
      });
      
      const result = await getDefaultBillingPlan(mockRealmId);
      
      expect(result).toBeDefined();
      expect(result?.is_default).toBe(true);
    });
    
    it('should return null when no default plan', async () => {
      mockSend.mockResolvedValueOnce({
        Items: []
      });
      
      const result = await getDefaultBillingPlan(mockRealmId);
      
      expect(result).toBeNull();
    });
  });

  describe('countBillingPlansByRealm', () => {
    it('should return count of non-archived plans', async () => {
      mockSend.mockResolvedValueOnce({
        Count: 5
      });
      
      const result = await countBillingPlansByRealm(mockRealmId);
      
      expect(result).toBe(5);
    });
    
    it('should return 0 when no plans', async () => {
      mockSend.mockResolvedValueOnce({
        Count: 0
      });
      
      const result = await countBillingPlansByRealm(mockRealmId);
      
      expect(result).toBe(0);
    });
  });

  describe('getBillingPlanByStripePriceId', () => {
    it('should return plan by monthly Stripe price ID', async () => {
      const mockPlan = {
        id: mockPlanId,
        realm_id: mockRealmId,
        name: 'Pro',
        type: 'per_user',
        price_monthly: 999,
        price_yearly: 9990,
        currency: 'usd',
        features: [],
        limits: {},
        status: 'active',
        stripe_price_id_monthly: 'price_monthly123',
        created_at: '2026-01-25T10:00:00Z'
      };
      
      mockSend.mockResolvedValueOnce({
        Items: [mockPlan]
      });
      
      const result = await getBillingPlanByStripePriceId(mockRealmId, 'price_monthly123');
      
      expect(result).toBeDefined();
      expect(result?.stripe_price_id_monthly).toBe('price_monthly123');
    });
    
    it('should return null when no matching plan', async () => {
      mockSend.mockResolvedValueOnce({
        Items: []
      });
      
      const result = await getBillingPlanByStripePriceId(mockRealmId, 'price_nonexistent');
      
      expect(result).toBeNull();
    });
  });

  describe('updateBillingPlan', () => {
    it('should update billing plan name', async () => {
      const updatedPlan = {
        id: mockPlanId,
        realm_id: mockRealmId,
        name: 'Updated Plan',
        type: 'per_user',
        price_monthly: 999,
        price_yearly: 9990,
        currency: 'usd',
        features: [],
        limits: {},
        status: 'active',
        created_at: '2026-01-25T10:00:00Z',
        updated_at: '2026-01-26T10:00:00Z'
      };
      
      mockSend.mockResolvedValueOnce({
        Attributes: updatedPlan
      });
      
      const result = await updateBillingPlan(mockRealmId, mockPlanId, {
        name: 'Updated Plan'
      });
      
      expect(result).toBeDefined();
      expect(result?.name).toBe('Updated Plan');
      expect(result?.updated_at).toBeDefined();
    });
    
    it('should update billing plan prices', async () => {
      const updatedPlan = {
        id: mockPlanId,
        realm_id: mockRealmId,
        name: 'Pro',
        type: 'per_user',
        price_monthly: 1999,
        price_yearly: 19990,
        currency: 'usd',
        features: [],
        limits: {},
        status: 'active',
        created_at: '2026-01-25T10:00:00Z',
        updated_at: '2026-01-26T10:00:00Z'
      };
      
      mockSend.mockResolvedValueOnce({
        Attributes: updatedPlan
      });
      
      const result = await updateBillingPlan(mockRealmId, mockPlanId, {
        price_monthly: 1999,
        price_yearly: 19990
      });
      
      expect(result).toBeDefined();
      expect(result?.price_monthly).toBe(1999);
      expect(result?.price_yearly).toBe(19990);
    });
    
    it('should reject invalid name on update', async () => {
      await expect(updateBillingPlan(mockRealmId, mockPlanId, {
        name: ''
      })).rejects.toThrow('Invalid plan name');
    });
    
    it('should reject invalid type on update', async () => {
      await expect(updateBillingPlan(mockRealmId, mockPlanId, {
        type: 'invalid' as BillingPlanType
      })).rejects.toThrow('Invalid billing plan type');
    });
    
    it('should reject invalid price on update', async () => {
      await expect(updateBillingPlan(mockRealmId, mockPlanId, {
        price_monthly: -100
      })).rejects.toThrow('Invalid monthly price');
    });
    
    it('should reject invalid status on update', async () => {
      await expect(updateBillingPlan(mockRealmId, mockPlanId, {
        status: 'invalid' as BillingPlanStatus
      })).rejects.toThrow('Invalid billing plan status');
    });
    
    it('should return null when plan not found', async () => {
      const error = new Error('ConditionalCheckFailedException');
      (error as Error & { name: string }).name = 'ConditionalCheckFailedException';
      mockSend.mockRejectedValueOnce(error);
      
      const result = await updateBillingPlan(mockRealmId, 'nonexistent', {
        name: 'New Name'
      });
      
      expect(result).toBeNull();
    });
  });

  describe('updateBillingPlanStatus', () => {
    it('should update billing plan status to inactive', async () => {
      const updatedPlan = {
        id: mockPlanId,
        realm_id: mockRealmId,
        name: 'Pro',
        type: 'per_user',
        price_monthly: 999,
        price_yearly: 9990,
        currency: 'usd',
        features: [],
        limits: {},
        status: 'inactive',
        created_at: '2026-01-25T10:00:00Z',
        updated_at: '2026-01-26T10:00:00Z'
      };
      
      mockSend.mockResolvedValueOnce({
        Attributes: updatedPlan
      });
      
      const result = await updateBillingPlanStatus(mockRealmId, mockPlanId, 'inactive');
      
      expect(result).toBeDefined();
      expect(result?.status).toBe('inactive');
    });
  });

  describe('setDefaultBillingPlan', () => {
    it('should set plan as default', async () => {
      // Mock listBillingPlansByRealm for unsetDefaultPlan (first call)
      mockSend.mockResolvedValueOnce({ Items: [] });
      
      // Mock updateBillingPlan - UpdateCommand (second call)
      const updatedPlan = {
        id: mockPlanId,
        realm_id: mockRealmId,
        name: 'Pro',
        type: 'per_user',
        price_monthly: 999,
        price_yearly: 9990,
        currency: 'usd',
        features: [],
        limits: {},
        status: 'active',
        is_default: true,
        created_at: '2026-01-25T10:00:00Z',
        updated_at: '2026-01-26T10:00:00Z'
      };
      
      mockSend.mockResolvedValueOnce({
        Attributes: updatedPlan
      });
      
      const result = await setDefaultBillingPlan(mockRealmId, mockPlanId);
      
      expect(result).toBeDefined();
      expect(result?.is_default).toBe(true);
    });
    
    it('should unset existing default before setting new one', async () => {
      // Mock listBillingPlansByRealm with existing default plan
      const existingDefaultPlan = {
        id: 'plan_old_default',
        realm_id: mockRealmId,
        name: 'Old Default',
        type: 'flat_rate',
        price_monthly: 0,
        price_yearly: 0,
        currency: 'usd',
        features: [],
        limits: {},
        status: 'active',
        is_default: true,
        created_at: '2026-01-25T10:00:00Z'
      };
      
      mockSend.mockResolvedValueOnce({ Items: [existingDefaultPlan] });
      
      // Mock UpdateCommand for unsetting old default
      mockSend.mockResolvedValueOnce({});
      
      // Mock UpdateCommand for setting new default
      const updatedPlan = {
        id: mockPlanId,
        realm_id: mockRealmId,
        name: 'Pro',
        type: 'per_user',
        price_monthly: 999,
        price_yearly: 9990,
        currency: 'usd',
        features: [],
        limits: {},
        status: 'active',
        is_default: true,
        created_at: '2026-01-25T10:00:00Z',
        updated_at: '2026-01-26T10:00:00Z'
      };
      
      mockSend.mockResolvedValueOnce({
        Attributes: updatedPlan
      });
      
      const result = await setDefaultBillingPlan(mockRealmId, mockPlanId);
      
      expect(result).toBeDefined();
      expect(result?.is_default).toBe(true);
      expect(mockSend).toHaveBeenCalledTimes(3);
    });
  });

  describe('archiveBillingPlan', () => {
    it('should archive billing plan (soft delete)', async () => {
      const archivedPlan = {
        id: mockPlanId,
        realm_id: mockRealmId,
        name: 'Pro',
        type: 'per_user',
        price_monthly: 999,
        price_yearly: 9990,
        currency: 'usd',
        features: [],
        limits: {},
        status: 'archived',
        created_at: '2026-01-25T10:00:00Z',
        updated_at: '2026-01-26T10:00:00Z'
      };
      
      mockSend.mockResolvedValueOnce({
        Attributes: archivedPlan
      });
      
      const result = await archiveBillingPlan(mockRealmId, mockPlanId);
      
      expect(result).toBe(true);
    });
    
    it('should return false when plan not found', async () => {
      const error = new Error('ConditionalCheckFailedException');
      (error as Error & { name: string }).name = 'ConditionalCheckFailedException';
      mockSend.mockRejectedValueOnce(error);
      
      const result = await archiveBillingPlan(mockRealmId, 'nonexistent');
      
      expect(result).toBe(false);
    });
  });

  describe('hardDeleteBillingPlan', () => {
    it('should permanently delete billing plan', async () => {
      mockSend.mockResolvedValueOnce({});
      
      const result = await hardDeleteBillingPlan(mockRealmId, mockPlanId);
      
      expect(result).toBe(true);
      expect(mockSend).toHaveBeenCalledTimes(1);
    });
    
    it('should return false on error', async () => {
      mockSend.mockRejectedValueOnce(new Error('DynamoDB error'));
      
      const result = await hardDeleteBillingPlan(mockRealmId, 'nonexistent');
      
      expect(result).toBe(false);
    });
  });

  describe('deleteAllRealmBillingPlans', () => {
    it('should delete all billing plans for a realm', async () => {
      const mockPlans = [
        { id: 'plan_1', realm_id: mockRealmId, name: 'Plan 1', type: 'flat_rate', price_monthly: 0, price_yearly: 0, currency: 'usd', features: [], limits: {}, status: 'active', created_at: '2026-01-25T10:00:00Z' },
        { id: 'plan_2', realm_id: mockRealmId, name: 'Plan 2', type: 'per_user', price_monthly: 999, price_yearly: 9990, currency: 'usd', features: [], limits: {}, status: 'active', created_at: '2026-01-26T10:00:00Z' }
      ];
      
      mockSend
        .mockResolvedValueOnce({ Items: mockPlans }) // listBillingPlansByRealm
        .mockResolvedValueOnce({}); // BatchWriteCommand
      
      const result = await deleteAllRealmBillingPlans(mockRealmId);
      
      expect(result).toBe(2);
    });
    
    it('should return 0 when no plans', async () => {
      mockSend.mockResolvedValueOnce({ Items: [] });
      
      const result = await deleteAllRealmBillingPlans(mockRealmId);
      
      expect(result).toBe(0);
    });
  });

  describe('countBillingPlansByStatus', () => {
    it('should count billing plans by status', async () => {
      const mockPlans = [
        { id: 'plan_1', status: 'active' },
        { id: 'plan_2', status: 'active' },
        { id: 'plan_3', status: 'inactive' },
        { id: 'plan_4', status: 'archived' }
      ];
      
      mockSend.mockResolvedValueOnce({ Items: mockPlans });
      
      const result = await countBillingPlansByStatus(mockRealmId);
      
      expect(result.active).toBe(2);
      expect(result.inactive).toBe(1);
      expect(result.archived).toBe(1);
    });
    
    it('should return zero counts when no plans', async () => {
      mockSend.mockResolvedValueOnce({ Items: [] });
      
      const result = await countBillingPlansByStatus(mockRealmId);
      
      expect(result.active).toBe(0);
      expect(result.inactive).toBe(0);
      expect(result.archived).toBe(0);
    });
  });
});
