/**
 * useBilling Hook - Billing and Subscription Management
 * Task 13.9: SDK useBilling() hook
 * 
 * Provides:
 * - Get current plan
 * - Check entitlements
 * - Get usage metrics
 * - Subscribe to plans
 * 
 * Validates: Requirements 7.7, 7.9 (Integrated Billing)
 */

import { useState, useEffect, useCallback, useMemo } from 'react';

/**
 * Billing plan types
 */
export type BillingPlanType = 'per_user' | 'per_org' | 'flat_rate' | 'usage_based';

/**
 * Billing interval
 */
export type BillingInterval = 'monthly' | 'yearly';

/**
 * Subscription status
 */
export type SubscriptionStatus = 'active' | 'past_due' | 'canceled' | 'trialing';

/**
 * Billing plan from API
 */
export interface BillingPlan {
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
  status: 'active' | 'inactive' | 'archived';
  trial_days?: number;
  is_default?: boolean;
  sort_order?: number;
  highlight_text?: string;
  created_at: string;
  updated_at?: string;
}

/**
 * Subscription from API
 */
export interface Subscription {
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
 * Usage metrics
 */
export interface UsageMetrics {
  tenant_id: string;
  period: string;
  mau: number;
  api_calls: number;
  storage_used?: number;
  features_used: Record<string, number>;
  limits: Record<string, number>;
  percentages: Record<string, number>;
}

/**
 * Entitlement check result
 */
export interface EntitlementResult {
  has_access: boolean;
  reason?: string;
  limit?: number;
  current_usage?: number;
  upgrade_required?: boolean;
}

/**
 * Subscribe input
 */
export interface SubscribeInput {
  plan_id: string;
  payment_method_id: string;
  interval?: BillingInterval;
  quantity?: number;
}

/**
 * Hook options
 */
export interface UseBillingOptions {
  /** API base URL */
  apiUrl?: string;
  /** Access token for API calls */
  accessToken?: string;
  /** Tenant ID for billing operations */
  tenantId?: string;
  /** Realm ID for fetching plans */
  realmId?: string;
  /** Auto-fetch plans on mount */
  autoFetchPlans?: boolean;
  /** Auto-fetch subscription on mount */
  autoFetchSubscription?: boolean;
}

/**
 * Hook return type
 */
export interface UseBillingReturn {
  /** Available billing plans */
  plans: BillingPlan[];
  /** Current subscription */
  subscription: Subscription | null;
  /** Current plan (from subscription) */
  currentPlan: BillingPlan | null;
  /** Usage metrics */
  usage: UsageMetrics | null;
  /** Loading state */
  isLoading: boolean;
  /** Error state */
  error: string | null;
  /** Fetch available plans */
  fetchPlans: (realmId?: string) => Promise<void>;
  /** Fetch current subscription */
  fetchSubscription: () => Promise<void>;
  /** Fetch usage metrics */
  fetchUsage: () => Promise<void>;
  /** Subscribe to a plan */
  subscribe: (input: SubscribeInput) => Promise<Subscription>;
  /** Cancel subscription */
  cancelSubscription: (cancelAtPeriodEnd?: boolean) => Promise<void>;
  /** Check if tenant has access to a feature */
  checkEntitlement: (feature: string) => Promise<EntitlementResult>;
  /** Check if feature is included in current plan (local check) */
  hasFeature: (feature: string) => boolean;
  /** Get limit value from current plan */
  getLimit: (limitKey: string) => number | undefined;
  /** Check if usage is within limit */
  isWithinLimit: (limitKey: string, currentUsage: number) => boolean;
  /** Calculate yearly savings percentage */
  getYearlySavings: (plan: BillingPlan) => number;
  /** Format price for display */
  formatPrice: (priceInCents: number, currency?: string) => string;
  /** Clear error */
  clearError: () => void;
  /** Refresh all billing data */
  refresh: () => Promise<void>;
}

/**
 * Format price for display
 */
function formatPriceValue(priceInCents: number, currency: string = 'usd'): string {
  const amount = priceInCents / 100;
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: currency.toUpperCase()
  }).format(amount);
}

/**
 * Calculate yearly savings percentage
 */
function calculateYearlySavings(priceMonthly: number, priceYearly: number): number {
  if (priceMonthly <= 0) return 0;
  const monthlyTotal = priceMonthly * 12;
  if (monthlyTotal <= priceYearly) return 0;
  return Math.round(((monthlyTotal - priceYearly) / monthlyTotal) * 100);
}

/**
 * useBilling Hook
 * 
 * Manages billing plans, subscriptions, and entitlements.
 * 
 * @example
 * ```tsx
 * const { plans, subscription, subscribe, hasFeature } = useBilling({
 *   realmId: 'your-realm-id',
 *   tenantId: 'your-tenant-id',
 *   accessToken: 'your-token'
 * });
 * 
 * // Check feature access
 * if (hasFeature('advanced_analytics')) {
 *   // Show advanced features
 * }
 * 
 * // Subscribe to a plan
 * await subscribe({
 *   plan_id: 'plan_xxx',
 *   payment_method_id: 'pm_xxx',
 *   interval: 'monthly'
 * });
 * ```
 */
export function useBilling(options: UseBillingOptions = {}): UseBillingReturn {
  const {
    apiUrl = '/api',
    accessToken,
    tenantId,
    realmId,
    autoFetchPlans = true,
    autoFetchSubscription = true
  } = options;

  // State
  const [plans, setPlans] = useState<BillingPlan[]>([]);
  const [subscription, setSubscription] = useState<Subscription | null>(null);
  const [usage, setUsage] = useState<UsageMetrics | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  /**
   * Get current plan from subscription
   */
  const currentPlan = useMemo(() => {
    if (!subscription) return null;
    return plans.find(p => p.id === subscription.plan_id) || null;
  }, [subscription, plans]);

  /**
   * Fetch available plans
   */
  const fetchPlans = useCallback(async (fetchRealmId?: string) => {
    const targetRealmId = fetchRealmId || realmId;
    if (!targetRealmId) {
      setError('Realm ID is required to fetch plans');
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      const response = await fetch(`${apiUrl}/billing/plans?realm_id=${targetRealmId}`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          ...(accessToken ? { 'Authorization': `Bearer ${accessToken}` } : {})
        }
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error?.message || 'Failed to fetch plans');
      }

      const data = await response.json();
      const fetchedPlans = data.data?.plans || data.plans || [];
      
      // Sort by sort_order
      fetchedPlans.sort((a: BillingPlan, b: BillingPlan) => {
        const orderA = a.sort_order ?? Number.MAX_SAFE_INTEGER;
        const orderB = b.sort_order ?? Number.MAX_SAFE_INTEGER;
        return orderA - orderB;
      });

      setPlans(fetchedPlans);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch plans');
    } finally {
      setIsLoading(false);
    }
  }, [apiUrl, accessToken, realmId]);

  /**
   * Fetch current subscription
   */
  const fetchSubscription = useCallback(async () => {
    if (!tenantId || !accessToken) {
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      const response = await fetch(`${apiUrl}/billing/subscription?tenant_id=${tenantId}`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json'
        }
      });

      if (!response.ok) {
        if (response.status === 404) {
          // No subscription found
          setSubscription(null);
          return;
        }
        const errorData = await response.json();
        throw new Error(errorData.error?.message || 'Failed to fetch subscription');
      }

      const data = await response.json();
      setSubscription(data.data || data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch subscription');
    } finally {
      setIsLoading(false);
    }
  }, [apiUrl, accessToken, tenantId]);

  /**
   * Fetch usage metrics
   */
  const fetchUsage = useCallback(async () => {
    if (!tenantId || !accessToken) {
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      const response = await fetch(`${apiUrl}/billing/usage?tenant_id=${tenantId}`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json'
        }
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error?.message || 'Failed to fetch usage');
      }

      const data = await response.json();
      setUsage(data.data || data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch usage');
    } finally {
      setIsLoading(false);
    }
  }, [apiUrl, accessToken, tenantId]);

  /**
   * Subscribe to a plan
   */
  const subscribeToPlan = useCallback(async (input: SubscribeInput): Promise<Subscription> => {
    if (!tenantId || !accessToken) {
      throw new Error('Tenant ID and access token are required');
    }

    setIsLoading(true);
    setError(null);

    try {
      const response = await fetch(`${apiUrl}/billing/subscribe`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          tenant_id: tenantId,
          plan_id: input.plan_id,
          payment_method_id: input.payment_method_id,
          interval: input.interval || 'monthly',
          quantity: input.quantity
        })
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error?.message || 'Failed to subscribe');
      }

      const data = await response.json();
      const newSubscription = data.data || data;
      setSubscription(newSubscription);
      return newSubscription;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to subscribe';
      setError(errorMessage);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [apiUrl, accessToken, tenantId]);

  /**
   * Cancel subscription
   */
  const cancelSubscription = useCallback(async (cancelAtPeriodEnd: boolean = true) => {
    if (!subscription || !accessToken) {
      throw new Error('No active subscription to cancel');
    }

    setIsLoading(true);
    setError(null);

    try {
      const response = await fetch(`${apiUrl}/billing/cancel`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          subscription_id: subscription.id,
          tenant_id: subscription.tenant_id,
          cancel_at_period_end: cancelAtPeriodEnd
        })
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error?.message || 'Failed to cancel subscription');
      }

      // Update local state
      if (cancelAtPeriodEnd) {
        setSubscription(prev => prev ? { ...prev, cancel_at_period_end: true } : null);
      } else {
        setSubscription(prev => prev ? { ...prev, status: 'canceled', canceled_at: new Date().toISOString() } : null);
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to cancel subscription';
      setError(errorMessage);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, [apiUrl, accessToken, subscription]);

  /**
   * Check entitlement via API
   */
  const checkEntitlement = useCallback(async (feature: string): Promise<EntitlementResult> => {
    if (!tenantId || !accessToken) {
      return { has_access: false, reason: 'Not authenticated' };
    }

    try {
      const response = await fetch(`${apiUrl}/billing/entitlement?tenant_id=${tenantId}&feature=${encodeURIComponent(feature)}`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json'
        }
      });

      if (!response.ok) {
        return { has_access: false, reason: 'Failed to check entitlement' };
      }

      const data = await response.json();
      return data.data || data;
    } catch {
      return { has_access: false, reason: 'Failed to check entitlement' };
    }
  }, [apiUrl, accessToken, tenantId]);

  /**
   * Check if feature is in current plan (local check)
   */
  const hasFeature = useCallback((feature: string): boolean => {
    if (!currentPlan) return false;
    return currentPlan.features.includes(feature);
  }, [currentPlan]);

  /**
   * Get limit value from current plan
   */
  const getLimit = useCallback((limitKey: string): number | undefined => {
    if (!currentPlan) return undefined;
    return currentPlan.limits[limitKey];
  }, [currentPlan]);

  /**
   * Check if usage is within limit
   */
  const isWithinLimit = useCallback((limitKey: string, currentUsage: number): boolean => {
    const limit = getLimit(limitKey);
    if (limit === undefined) return true; // No limit = unlimited
    return currentUsage <= limit;
  }, [getLimit]);

  /**
   * Get yearly savings for a plan
   */
  const getYearlySavings = useCallback((plan: BillingPlan): number => {
    return calculateYearlySavings(plan.price_monthly, plan.price_yearly);
  }, []);

  /**
   * Format price for display
   */
  const formatPrice = useCallback((priceInCents: number, currency?: string): string => {
    return formatPriceValue(priceInCents, currency || currentPlan?.currency || 'usd');
  }, [currentPlan]);

  /**
   * Clear error
   */
  const clearError = useCallback(() => {
    setError(null);
  }, []);

  /**
   * Refresh all billing data
   */
  const refresh = useCallback(async () => {
    await Promise.all([
      fetchPlans(),
      fetchSubscription(),
      fetchUsage()
    ]);
  }, [fetchPlans, fetchSubscription, fetchUsage]);

  /**
   * Auto-fetch on mount
   */
  useEffect(() => {
    if (autoFetchPlans && realmId) {
      fetchPlans();
    }
  }, [autoFetchPlans, realmId, fetchPlans]);

  useEffect(() => {
    if (autoFetchSubscription && tenantId && accessToken) {
      fetchSubscription();
    }
  }, [autoFetchSubscription, tenantId, accessToken, fetchSubscription]);

  return {
    plans,
    subscription,
    currentPlan,
    usage,
    isLoading,
    error,
    fetchPlans,
    fetchSubscription,
    fetchUsage,
    subscribe: subscribeToPlan,
    cancelSubscription,
    checkEntitlement,
    hasFeature,
    getLimit,
    isWithinLimit,
    getYearlySavings,
    formatPrice,
    clearError,
    refresh
  };
}

export default useBilling;
