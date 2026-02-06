/**
 * useBilling Hook Tests
 * Task 13.9: SDK useBilling() hook
 * 
 * Validates: Requirement 7.9 (Integrated Billing)
 * 
 * Tests:
 * - Get current plan
 * - Check entitlements
 * - Get usage metrics
 * - Subscribe to plans
 * - Cancel subscription
 */

import { renderHook, act, waitFor } from '@testing-library/react';
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { useBilling, BillingPlan, Subscription, UsageMetrics } from '../useBilling';

// Mock fetch
const mockFetch = vi.fn();
global.fetch = mockFetch;

// Configure test timeout
vi.setConfig({ testTimeout: 10000 });

describe('useBilling', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const defaultOptions = {
    apiUrl: '/api',
    accessToken: 'test-token',
    tenantId: 'tenant-123',
    realmId: 'realm-456',
    autoFetchPlans: false,
    autoFetchSubscription: false
  };

  const mockPlans: BillingPlan[] = [
    {
      id: 'plan_free',
      realm_id: 'realm-456',
      name: 'Free',
      description: 'Perfect for getting started',
      type: 'flat_rate',
      price_monthly: 0,
      price_yearly: 0,
      currency: 'usd',
      features: ['5 users', 'Basic support'],
      limits: { users: 5, api_calls: 1000 },
      status: 'active',
      sort_order: 1,
      created_at: '2024-01-01T00:00:00Z'
    },
    {
      id: 'plan_pro',
      realm_id: 'realm-456',
      name: 'Pro',
      description: 'For growing teams',
      type: 'per_user',
      price_monthly: 2900,
      price_yearly: 29000,
      currency: 'usd',
      features: ['Unlimited users', 'Priority support', 'advanced_analytics'],
      limits: { users: -1, api_calls: 100000 },
      status: 'active',
      sort_order: 2,
      highlight_text: 'Most Popular',
      trial_days: 14,
      created_at: '2024-01-01T00:00:00Z'
    },
    {
      id: 'plan_enterprise',
      realm_id: 'realm-456',
      name: 'Enterprise',
      description: 'For large organizations',
      type: 'flat_rate',
      price_monthly: 9900,
      price_yearly: 99000,
      currency: 'usd',
      features: ['Unlimited users', 'Dedicated support', 'advanced_analytics', 'sso', 'audit_logs'],
      limits: { users: -1, api_calls: -1 },
      status: 'active',
      sort_order: 3,
      created_at: '2024-01-01T00:00:00Z'
    }
  ];

  const mockSubscription: Subscription = {
    id: 'sub_123',
    tenant_id: 'tenant-123',
    plan_id: 'plan_pro',
    stripe_subscription_id: 'sub_stripe123',
    status: 'active',
    current_period_start: '2024-01-01T00:00:00Z',
    current_period_end: '2024-02-01T00:00:00Z',
    created_at: '2024-01-01T00:00:00Z'
  };

  const mockUsage: UsageMetrics = {
    tenant_id: 'tenant-123',
    period: '2024-01',
    mau: 150,
    api_calls: 45000,
    storage_used: 5000,
    features_used: { advanced_analytics: 25, sso: 0 },
    limits: { api_calls: 100000, storage_gb: 100 },
    percentages: { api_calls: 45, storage: 5 }
  };

  describe('initial state', () => {
    it('should start with empty state', () => {
      const { result } = renderHook(() => useBilling(defaultOptions));

      expect(result.current.plans).toEqual([]);
      expect(result.current.subscription).toBeNull();
      expect(result.current.currentPlan).toBeNull();
      expect(result.current.usage).toBeNull();
      expect(result.current.isLoading).toBe(false);
      expect(result.current.error).toBeNull();
    });

    it('should not auto-fetch when disabled', () => {
      renderHook(() => useBilling(defaultOptions));
      expect(mockFetch).not.toHaveBeenCalled();
    });
  });

  describe('fetchPlans', () => {
    it('should fetch plans successfully', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ data: { plans: mockPlans } })
      });

      const { result } = renderHook(() => useBilling(defaultOptions));

      await act(async () => {
        await result.current.fetchPlans();
      });

      expect(mockFetch).toHaveBeenCalledWith(
        '/api/billing/plans?realm_id=realm-456',
        expect.objectContaining({
          method: 'GET',
          headers: expect.objectContaining({
            'Authorization': 'Bearer test-token'
          })
        })
      );
      expect(result.current.plans).toHaveLength(3);
      expect(result.current.plans[0].name).toBe('Free');
    });

    it('should sort plans by sort_order', async () => {
      const unsortedPlans = [mockPlans[2], mockPlans[0], mockPlans[1]];
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ data: { plans: unsortedPlans } })
      });

      const { result } = renderHook(() => useBilling(defaultOptions));

      await act(async () => {
        await result.current.fetchPlans();
      });

      expect(result.current.plans[0].sort_order).toBe(1);
      expect(result.current.plans[1].sort_order).toBe(2);
      expect(result.current.plans[2].sort_order).toBe(3);
    });

    it('should handle fetch plans error', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        json: () => Promise.resolve({ error: { message: 'Unauthorized' } })
      });

      const { result } = renderHook(() => useBilling(defaultOptions));

      await act(async () => {
        await result.current.fetchPlans();
      });

      expect(result.current.error).toBe('Unauthorized');
      expect(result.current.plans).toEqual([]);
    });

    it('should require realm ID', async () => {
      const { result } = renderHook(() => useBilling({ ...defaultOptions, realmId: undefined }));

      await act(async () => {
        await result.current.fetchPlans();
      });

      expect(result.current.error).toBe('Realm ID is required to fetch plans');
      expect(mockFetch).not.toHaveBeenCalled();
    });
  });

  describe('fetchSubscription', () => {
    it('should fetch subscription successfully', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ data: mockSubscription })
      });

      const { result } = renderHook(() => useBilling(defaultOptions));

      await act(async () => {
        await result.current.fetchSubscription();
      });

      expect(mockFetch).toHaveBeenCalledWith(
        '/api/billing/subscription?tenant_id=tenant-123',
        expect.objectContaining({
          method: 'GET',
          headers: expect.objectContaining({
            'Authorization': 'Bearer test-token'
          })
        })
      );
      expect(result.current.subscription).toEqual(mockSubscription);
    });

    it('should handle no subscription (404)', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
        json: () => Promise.resolve({ error: { message: 'Not found' } })
      });

      const { result } = renderHook(() => useBilling(defaultOptions));

      await act(async () => {
        await result.current.fetchSubscription();
      });

      expect(result.current.subscription).toBeNull();
      expect(result.current.error).toBeNull();
    });

    it('should not fetch without tenant ID', async () => {
      const { result } = renderHook(() => useBilling({ ...defaultOptions, tenantId: undefined }));

      await act(async () => {
        await result.current.fetchSubscription();
      });

      expect(mockFetch).not.toHaveBeenCalled();
    });

    it('should not fetch without access token', async () => {
      const { result } = renderHook(() => useBilling({ ...defaultOptions, accessToken: undefined }));

      await act(async () => {
        await result.current.fetchSubscription();
      });

      expect(mockFetch).not.toHaveBeenCalled();
    });
  });

  describe('fetchUsage', () => {
    it('should fetch usage metrics successfully', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ data: mockUsage })
      });

      const { result } = renderHook(() => useBilling(defaultOptions));

      await act(async () => {
        await result.current.fetchUsage();
      });

      expect(mockFetch).toHaveBeenCalledWith(
        '/api/billing/usage?tenant_id=tenant-123',
        expect.objectContaining({
          method: 'GET',
          headers: expect.objectContaining({
            'Authorization': 'Bearer test-token'
          })
        })
      );
      expect(result.current.usage).toEqual(mockUsage);
    });

    it('should handle fetch usage error', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        json: () => Promise.resolve({ error: { message: 'Failed to fetch usage' } })
      });

      const { result } = renderHook(() => useBilling(defaultOptions));

      await act(async () => {
        await result.current.fetchUsage();
      });

      expect(result.current.error).toBe('Failed to fetch usage');
    });
  });

  describe('currentPlan', () => {
    it('should return current plan from subscription', async () => {
      // First fetch plans
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ data: { plans: mockPlans } })
      });

      const { result } = renderHook(() => useBilling(defaultOptions));

      await act(async () => {
        await result.current.fetchPlans();
      });

      // Then fetch subscription
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ data: mockSubscription })
      });

      await act(async () => {
        await result.current.fetchSubscription();
      });

      expect(result.current.currentPlan).toBeTruthy();
      expect(result.current.currentPlan?.id).toBe('plan_pro');
      expect(result.current.currentPlan?.name).toBe('Pro');
    });

    it('should return null when no subscription', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ data: { plans: mockPlans } })
      });

      const { result } = renderHook(() => useBilling(defaultOptions));

      await act(async () => {
        await result.current.fetchPlans();
      });

      expect(result.current.currentPlan).toBeNull();
    });
  });

  describe('subscribe', () => {
    it('should subscribe to a plan successfully', async () => {
      const newSubscription: Subscription = {
        ...mockSubscription,
        id: 'sub_new',
        plan_id: 'plan_enterprise'
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ data: newSubscription })
      });

      const { result } = renderHook(() => useBilling(defaultOptions));

      let subscription: Subscription | undefined;
      await act(async () => {
        subscription = await result.current.subscribe({
          plan_id: 'plan_enterprise',
          payment_method_id: 'pm_test123',
          interval: 'monthly'
        });
      });

      expect(mockFetch).toHaveBeenCalledWith(
        '/api/billing/subscribe',
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Authorization': 'Bearer test-token',
            'Content-Type': 'application/json'
          }),
          body: JSON.stringify({
            tenant_id: 'tenant-123',
            plan_id: 'plan_enterprise',
            payment_method_id: 'pm_test123',
            interval: 'monthly',
            quantity: undefined
          })
        })
      );
      expect(subscription).toEqual(newSubscription);
      expect(result.current.subscription).toEqual(newSubscription);
    });

    it('should handle subscribe error', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        json: () => Promise.resolve({ error: { message: 'Payment failed' } })
      });

      const { result } = renderHook(() => useBilling(defaultOptions));

      await act(async () => {
        try {
          await result.current.subscribe({
            plan_id: 'plan_pro',
            payment_method_id: 'pm_invalid'
          });
        } catch (error) {
          expect((error as Error).message).toBe('Payment failed');
        }
      });

      expect(result.current.error).toBe('Payment failed');
    });

    it('should throw error without tenant ID', async () => {
      const { result } = renderHook(() => useBilling({ ...defaultOptions, tenantId: undefined }));

      await act(async () => {
        try {
          await result.current.subscribe({
            plan_id: 'plan_pro',
            payment_method_id: 'pm_test'
          });
        } catch (error) {
          expect((error as Error).message).toBe('Tenant ID and access token are required');
        }
      });
    });
  });

  describe('cancelSubscription', () => {
    it('should cancel subscription at period end', async () => {
      // First set up subscription
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ data: mockSubscription })
      });

      const { result } = renderHook(() => useBilling(defaultOptions));

      await act(async () => {
        await result.current.fetchSubscription();
      });

      // Then cancel
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ data: { message: 'Subscription canceled' } })
      });

      await act(async () => {
        await result.current.cancelSubscription(true);
      });

      expect(mockFetch).toHaveBeenLastCalledWith(
        '/api/billing/cancel',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({
            subscription_id: 'sub_123',
            tenant_id: 'tenant-123',
            cancel_at_period_end: true
          })
        })
      );
      expect(result.current.subscription?.cancel_at_period_end).toBe(true);
    });

    it('should cancel subscription immediately', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ data: mockSubscription })
      });

      const { result } = renderHook(() => useBilling(defaultOptions));

      await act(async () => {
        await result.current.fetchSubscription();
      });

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ data: { message: 'Subscription canceled' } })
      });

      await act(async () => {
        await result.current.cancelSubscription(false);
      });

      expect(result.current.subscription?.status).toBe('canceled');
    });

    it('should throw error without subscription', async () => {
      const { result } = renderHook(() => useBilling(defaultOptions));

      await act(async () => {
        try {
          await result.current.cancelSubscription();
        } catch (error) {
          expect((error as Error).message).toBe('No active subscription to cancel');
        }
      });
    });
  });

  describe('checkEntitlement', () => {
    it('should check entitlement via API', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          data: {
            has_access: true,
            limit: 100000,
            current_usage: 45000
          }
        })
      });

      const { result } = renderHook(() => useBilling(defaultOptions));

      let entitlement;
      await act(async () => {
        entitlement = await result.current.checkEntitlement('api_calls');
      });

      expect(mockFetch).toHaveBeenCalledWith(
        '/api/billing/entitlement?tenant_id=tenant-123&feature=api_calls',
        expect.objectContaining({
          method: 'GET',
          headers: expect.objectContaining({
            'Authorization': 'Bearer test-token'
          })
        })
      );
      expect(entitlement).toEqual({
        has_access: true,
        limit: 100000,
        current_usage: 45000
      });
    });

    it('should return no access without authentication', async () => {
      const { result } = renderHook(() => useBilling({ ...defaultOptions, tenantId: undefined }));

      let entitlement;
      await act(async () => {
        entitlement = await result.current.checkEntitlement('api_calls');
      });

      expect(entitlement).toEqual({
        has_access: false,
        reason: 'Not authenticated'
      });
    });

    it('should handle entitlement check error', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        json: () => Promise.resolve({ error: { message: 'Server error' } })
      });

      const { result } = renderHook(() => useBilling(defaultOptions));

      let entitlement;
      await act(async () => {
        entitlement = await result.current.checkEntitlement('api_calls');
      });

      expect(entitlement).toEqual({
        has_access: false,
        reason: 'Failed to check entitlement'
      });
    });
  });

  describe('hasFeature (local check)', () => {
    it('should return true for included feature', async () => {
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: { plans: mockPlans } })
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: mockSubscription })
        });

      const { result } = renderHook(() => useBilling(defaultOptions));

      await act(async () => {
        await result.current.fetchPlans();
        await result.current.fetchSubscription();
      });

      expect(result.current.hasFeature('advanced_analytics')).toBe(true);
      expect(result.current.hasFeature('Priority support')).toBe(true);
    });

    it('should return false for non-included feature', async () => {
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: { plans: mockPlans } })
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: mockSubscription })
        });

      const { result } = renderHook(() => useBilling(defaultOptions));

      await act(async () => {
        await result.current.fetchPlans();
        await result.current.fetchSubscription();
      });

      // Pro plan doesn't have 'sso' feature
      expect(result.current.hasFeature('sso')).toBe(false);
    });

    it('should return false without current plan', () => {
      const { result } = renderHook(() => useBilling(defaultOptions));
      expect(result.current.hasFeature('any_feature')).toBe(false);
    });
  });

  describe('getLimit', () => {
    it('should return limit value from current plan', async () => {
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: { plans: mockPlans } })
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: mockSubscription })
        });

      const { result } = renderHook(() => useBilling(defaultOptions));

      await act(async () => {
        await result.current.fetchPlans();
        await result.current.fetchSubscription();
      });

      expect(result.current.getLimit('api_calls')).toBe(100000);
      expect(result.current.getLimit('users')).toBe(-1); // Unlimited
    });

    it('should return undefined for non-existent limit', async () => {
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: { plans: mockPlans } })
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: mockSubscription })
        });

      const { result } = renderHook(() => useBilling(defaultOptions));

      await act(async () => {
        await result.current.fetchPlans();
        await result.current.fetchSubscription();
      });

      expect(result.current.getLimit('non_existent')).toBeUndefined();
    });

    it('should return undefined without current plan', () => {
      const { result } = renderHook(() => useBilling(defaultOptions));
      expect(result.current.getLimit('api_calls')).toBeUndefined();
    });
  });

  describe('isWithinLimit', () => {
    it('should return true when within limit', async () => {
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: { plans: mockPlans } })
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: mockSubscription })
        });

      const { result } = renderHook(() => useBilling(defaultOptions));

      await act(async () => {
        await result.current.fetchPlans();
        await result.current.fetchSubscription();
      });

      expect(result.current.isWithinLimit('api_calls', 50000)).toBe(true);
      expect(result.current.isWithinLimit('api_calls', 100000)).toBe(true);
    });

    it('should return false when exceeding limit', async () => {
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: { plans: mockPlans } })
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: mockSubscription })
        });

      const { result } = renderHook(() => useBilling(defaultOptions));

      await act(async () => {
        await result.current.fetchPlans();
        await result.current.fetchSubscription();
      });

      expect(result.current.isWithinLimit('api_calls', 100001)).toBe(false);
    });

    it('should return true when no limit defined (unlimited)', async () => {
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: { plans: mockPlans } })
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: mockSubscription })
        });

      const { result } = renderHook(() => useBilling(defaultOptions));

      await act(async () => {
        await result.current.fetchPlans();
        await result.current.fetchSubscription();
      });

      // Non-existent limit = unlimited
      expect(result.current.isWithinLimit('non_existent', 999999)).toBe(true);
    });
  });

  describe('getYearlySavings', () => {
    it('should calculate yearly savings percentage', () => {
      const { result } = renderHook(() => useBilling(defaultOptions));

      // Pro plan: $29/month = $348/year, yearly price = $290
      // Savings = (348 - 290) / 348 = 16.67%
      const savings = result.current.getYearlySavings(mockPlans[1]);
      expect(savings).toBe(17); // Rounded
    });

    it('should return 0 for free plans', () => {
      const { result } = renderHook(() => useBilling(defaultOptions));

      const savings = result.current.getYearlySavings(mockPlans[0]);
      expect(savings).toBe(0);
    });

    it('should return 0 when yearly is more expensive', () => {
      const { result } = renderHook(() => useBilling(defaultOptions));

      const expensivePlan: BillingPlan = {
        ...mockPlans[1],
        price_monthly: 1000,
        price_yearly: 15000 // More than 12 * 1000
      };

      const savings = result.current.getYearlySavings(expensivePlan);
      expect(savings).toBe(0);
    });
  });

  describe('formatPrice', () => {
    it('should format price in USD', async () => {
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: { plans: mockPlans } })
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: mockSubscription })
        });

      const { result } = renderHook(() => useBilling(defaultOptions));

      await act(async () => {
        await result.current.fetchPlans();
        await result.current.fetchSubscription();
      });

      expect(result.current.formatPrice(2900)).toBe('$29.00');
      expect(result.current.formatPrice(9900)).toBe('$99.00');
      expect(result.current.formatPrice(0)).toBe('$0.00');
    });

    it('should format price with custom currency', () => {
      const { result } = renderHook(() => useBilling(defaultOptions));

      expect(result.current.formatPrice(2900, 'eur')).toBe('€29.00');
      expect(result.current.formatPrice(2900, 'gbp')).toBe('£29.00');
    });
  });

  describe('clearError', () => {
    it('should clear error state', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        json: () => Promise.resolve({ error: { message: 'Some error' } })
      });

      const { result } = renderHook(() => useBilling(defaultOptions));

      await act(async () => {
        await result.current.fetchPlans();
      });

      expect(result.current.error).toBe('Some error');

      act(() => {
        result.current.clearError();
      });

      expect(result.current.error).toBeNull();
    });
  });

  describe('refresh', () => {
    it('should refresh all billing data', async () => {
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: { plans: mockPlans } })
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: mockSubscription })
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: mockUsage })
        });

      const { result } = renderHook(() => useBilling(defaultOptions));

      await act(async () => {
        await result.current.refresh();
      });

      expect(mockFetch).toHaveBeenCalledTimes(3);
      expect(result.current.plans).toHaveLength(3);
      expect(result.current.subscription).toEqual(mockSubscription);
      expect(result.current.usage).toEqual(mockUsage);
    });
  });

  describe('auto-fetch on mount', () => {
    it('should auto-fetch plans when enabled', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ data: { plans: mockPlans } })
      });

      const { result } = renderHook(() => useBilling({
        ...defaultOptions,
        autoFetchPlans: true
      }));

      await waitFor(() => {
        expect(result.current.plans).toHaveLength(3);
      });

      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/billing/plans'),
        expect.any(Object)
      );
    });

    it('should auto-fetch subscription when enabled', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ data: mockSubscription })
      });

      const { result } = renderHook(() => useBilling({
        ...defaultOptions,
        autoFetchSubscription: true
      }));

      await waitFor(() => {
        expect(result.current.subscription).toEqual(mockSubscription);
      });

      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/billing/subscription'),
        expect.any(Object)
      );
    });
  });

  describe('loading states', () => {
    it('should set loading during fetch', async () => {
      let resolvePromise: (value: unknown) => void;
      const promise = new Promise(resolve => {
        resolvePromise = resolve;
      });

      mockFetch.mockReturnValueOnce(promise);

      const { result } = renderHook(() => useBilling(defaultOptions));

      act(() => {
        result.current.fetchPlans();
      });

      expect(result.current.isLoading).toBe(true);

      await act(async () => {
        resolvePromise!({
          ok: true,
          json: () => Promise.resolve({ data: { plans: mockPlans } })
        });
      });

      expect(result.current.isLoading).toBe(false);
    });
  });

  describe('error handling', () => {
    it('should handle network error', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Network error'));

      const { result } = renderHook(() => useBilling(defaultOptions));

      await act(async () => {
        await result.current.fetchPlans();
      });

      expect(result.current.error).toBe('Network error');
    });

    it('should handle non-Error rejection', async () => {
      mockFetch.mockRejectedValueOnce('Unknown error');

      const { result } = renderHook(() => useBilling(defaultOptions));

      await act(async () => {
        await result.current.fetchPlans();
      });

      expect(result.current.error).toBe('Failed to fetch plans');
    });
  });

  describe('subscription status handling', () => {
    it('should handle trialing subscription', async () => {
      const trialingSubscription: Subscription = {
        ...mockSubscription,
        status: 'trialing',
        trial_start: '2024-01-01T00:00:00Z',
        trial_end: '2024-01-15T00:00:00Z'
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ data: trialingSubscription })
      });

      const { result } = renderHook(() => useBilling(defaultOptions));

      await act(async () => {
        await result.current.fetchSubscription();
      });

      expect(result.current.subscription?.status).toBe('trialing');
      expect(result.current.subscription?.trial_end).toBe('2024-01-15T00:00:00Z');
    });

    it('should handle past_due subscription', async () => {
      const pastDueSubscription: Subscription = {
        ...mockSubscription,
        status: 'past_due'
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ data: pastDueSubscription })
      });

      const { result } = renderHook(() => useBilling(defaultOptions));

      await act(async () => {
        await result.current.fetchSubscription();
      });

      expect(result.current.subscription?.status).toBe('past_due');
    });

    it('should handle canceled subscription', async () => {
      const canceledSubscription: Subscription = {
        ...mockSubscription,
        status: 'canceled',
        canceled_at: '2024-01-15T00:00:00Z'
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ data: canceledSubscription })
      });

      const { result } = renderHook(() => useBilling(defaultOptions));

      await act(async () => {
        await result.current.fetchSubscription();
      });

      expect(result.current.subscription?.status).toBe('canceled');
      expect(result.current.subscription?.canceled_at).toBe('2024-01-15T00:00:00Z');
    });
  });
});
