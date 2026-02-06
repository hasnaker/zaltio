/**
 * PricingTable Component
 * @zalt/react
 * 
 * Component for displaying billing plans and allowing subscription.
 * Shows plan comparison with features, pricing, and subscribe actions.
 * 
 * Validates: Requirement 7.7
 */

'use client';

import React, { useState, useCallback, useEffect, useMemo } from 'react';

// ============================================================================
// Types
// ============================================================================

/**
 * Billing plan type
 */
export type BillingPlanType = 'per_user' | 'per_org' | 'flat_rate' | 'usage_based';

/**
 * Billing interval
 */
export type BillingInterval = 'monthly' | 'yearly';

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
 * Subscribe result
 */
export interface SubscribeResult {
  subscription_id: string;
  plan_id: string;
  status: string;
  client_secret?: string;
}

/**
 * PricingTable props
 */
export interface PricingTableProps {
  /** Realm ID for fetching plans */
  realmId: string;
  /** API base URL */
  apiUrl?: string;
  /** Access token for authenticated requests */
  accessToken?: string;
  /** Tenant ID for subscription */
  tenantId?: string;
  /** Current plan ID (to show as selected) */
  currentPlanId?: string;
  /** Default billing interval */
  defaultInterval?: BillingInterval;
  /** Show interval toggle */
  showIntervalToggle?: boolean;
  /** Show feature comparison */
  showFeatures?: boolean;
  /** Maximum features to show per plan */
  maxFeaturesShown?: number;
  /** Custom class name */
  className?: string;
  /** Callback when user clicks subscribe */
  onSubscribe?: (planId: string, interval: BillingInterval) => Promise<void>;
  /** Callback when subscription succeeds */
  onSubscribeSuccess?: (result: SubscribeResult) => void;
  /** Callback on error */
  onError?: (error: Error) => void;
  /** Custom subscribe button text */
  subscribeButtonText?: string;
  /** Custom current plan button text */
  currentPlanButtonText?: string;
  /** Custom upgrade button text */
  upgradeButtonText?: string;
  /** Custom downgrade button text */
  downgradeButtonText?: string;
  /** Show contact sales for enterprise */
  showContactSales?: boolean;
  /** Contact sales URL or callback */
  onContactSales?: () => void;
  /** Compact mode */
  compact?: boolean;
  /** Highlight recommended plan */
  highlightRecommended?: boolean;
  /** Plans to display (if not fetching from API) */
  plans?: BillingPlan[];
  /** Currency override */
  currency?: string;
}

// ============================================================================
// Styles
// ============================================================================

const styles = {
  container: {
    fontFamily: 'var(--zalt-font, system-ui, sans-serif)',
    color: 'var(--zalt-text, #fff)',
    maxWidth: '1200px',
    margin: '0 auto',
    padding: '24px',
  } as React.CSSProperties,

  header: {
    textAlign: 'center' as const,
    marginBottom: '32px',
  } as React.CSSProperties,

  intervalToggle: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: '12px',
    padding: '4px',
    background: 'rgba(255,255,255,0.1)',
    borderRadius: 'var(--zalt-radius, 0.5rem)',
    marginBottom: '24px',
  } as React.CSSProperties,

  intervalButton: {
    padding: '10px 20px',
    border: 'none',
    borderRadius: 'calc(var(--zalt-radius, 0.5rem) - 2px)',
    fontSize: '14px',
    fontWeight: 500,
    cursor: 'pointer',
    transition: 'all 0.15s',
    background: 'transparent',
    color: 'rgba(255,255,255,0.7)',
  } as React.CSSProperties,

  intervalButtonActive: {
    background: 'var(--zalt-primary, #10b981)',
    color: '#000',
  } as React.CSSProperties,

  savingsBadge: {
    display: 'inline-block',
    padding: '2px 8px',
    background: 'rgba(16, 185, 129, 0.2)',
    color: 'var(--zalt-primary, #10b981)',
    borderRadius: '9999px',
    fontSize: '12px',
    fontWeight: 600,
    marginLeft: '8px',
  } as React.CSSProperties,

  grid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
    gap: '24px',
    alignItems: 'stretch',
  } as React.CSSProperties,

  card: {
    background: 'rgba(255,255,255,0.05)',
    borderRadius: 'var(--zalt-radius, 0.75rem)',
    padding: '24px',
    border: '1px solid rgba(255,255,255,0.1)',
    display: 'flex',
    flexDirection: 'column' as const,
    position: 'relative' as const,
    transition: 'transform 0.15s, box-shadow 0.15s',
  } as React.CSSProperties,

  cardHighlighted: {
    border: '2px solid var(--zalt-primary, #10b981)',
    transform: 'scale(1.02)',
    boxShadow: '0 8px 32px rgba(16, 185, 129, 0.2)',
  } as React.CSSProperties,

  cardCurrent: {
    border: '2px solid rgba(255,255,255,0.3)',
  } as React.CSSProperties,

  highlightBadge: {
    position: 'absolute' as const,
    top: '-12px',
    left: '50%',
    transform: 'translateX(-50%)',
    padding: '4px 16px',
    background: 'var(--zalt-primary, #10b981)',
    color: '#000',
    borderRadius: '9999px',
    fontSize: '12px',
    fontWeight: 600,
    textTransform: 'uppercase' as const,
    whiteSpace: 'nowrap' as const,
  } as React.CSSProperties,

  planName: {
    fontSize: '20px',
    fontWeight: 600,
    margin: '0 0 8px 0',
  } as React.CSSProperties,

  planDescription: {
    fontSize: '14px',
    color: 'rgba(255,255,255,0.6)',
    margin: '0 0 16px 0',
    minHeight: '40px',
  } as React.CSSProperties,

  priceContainer: {
    marginBottom: '24px',
  } as React.CSSProperties,

  price: {
    fontSize: '48px',
    fontWeight: 700,
    lineHeight: 1,
  } as React.CSSProperties,

  priceCurrency: {
    fontSize: '24px',
    fontWeight: 500,
    verticalAlign: 'top',
  } as React.CSSProperties,

  priceInterval: {
    fontSize: '14px',
    color: 'rgba(255,255,255,0.6)',
    marginLeft: '4px',
  } as React.CSSProperties,

  originalPrice: {
    fontSize: '14px',
    color: 'rgba(255,255,255,0.4)',
    textDecoration: 'line-through',
    marginTop: '4px',
  } as React.CSSProperties,

  trialBadge: {
    display: 'inline-block',
    padding: '4px 12px',
    background: 'rgba(59, 130, 246, 0.2)',
    color: '#3b82f6',
    borderRadius: 'var(--zalt-radius, 0.25rem)',
    fontSize: '12px',
    fontWeight: 500,
    marginTop: '8px',
  } as React.CSSProperties,

  features: {
    flex: 1,
    marginBottom: '24px',
  } as React.CSSProperties,

  featuresTitle: {
    fontSize: '13px',
    fontWeight: 600,
    color: 'rgba(255,255,255,0.5)',
    textTransform: 'uppercase' as const,
    letterSpacing: '0.5px',
    marginBottom: '12px',
  } as React.CSSProperties,

  featureList: {
    listStyle: 'none',
    padding: 0,
    margin: 0,
  } as React.CSSProperties,

  featureItem: {
    display: 'flex',
    alignItems: 'flex-start',
    gap: '10px',
    padding: '8px 0',
    fontSize: '14px',
    color: 'rgba(255,255,255,0.8)',
  } as React.CSSProperties,

  featureIcon: {
    flexShrink: 0,
    width: '18px',
    height: '18px',
    color: 'var(--zalt-primary, #10b981)',
  } as React.CSSProperties,

  moreFeatures: {
    fontSize: '13px',
    color: 'rgba(255,255,255,0.5)',
    marginTop: '8px',
    fontStyle: 'italic',
  } as React.CSSProperties,

  limits: {
    marginBottom: '24px',
    padding: '12px',
    background: 'rgba(255,255,255,0.03)',
    borderRadius: 'var(--zalt-radius, 0.5rem)',
  } as React.CSSProperties,

  limitItem: {
    display: 'flex',
    justifyContent: 'space-between',
    fontSize: '13px',
    padding: '4px 0',
    color: 'rgba(255,255,255,0.7)',
  } as React.CSSProperties,

  limitValue: {
    fontWeight: 600,
    color: 'var(--zalt-text, #fff)',
  } as React.CSSProperties,

  button: {
    width: '100%',
    padding: '14px 24px',
    background: 'var(--zalt-primary, #10b981)',
    color: '#000',
    border: 'none',
    borderRadius: 'var(--zalt-radius, 0.5rem)',
    fontSize: '15px',
    fontWeight: 600,
    cursor: 'pointer',
    transition: 'opacity 0.15s, transform 0.1s',
  } as React.CSSProperties,

  buttonSecondary: {
    background: 'transparent',
    color: 'var(--zalt-primary, #10b981)',
    border: '2px solid var(--zalt-primary, #10b981)',
  } as React.CSSProperties,

  buttonDisabled: {
    opacity: 0.6,
    cursor: 'not-allowed',
  } as React.CSSProperties,

  buttonCurrent: {
    background: 'rgba(255,255,255,0.1)',
    color: 'rgba(255,255,255,0.6)',
    cursor: 'default',
  } as React.CSSProperties,

  error: {
    padding: '16px',
    background: 'rgba(239, 68, 68, 0.1)',
    border: '1px solid rgba(239, 68, 68, 0.3)',
    borderRadius: 'var(--zalt-radius, 0.5rem)',
    color: '#ef4444',
    fontSize: '14px',
    textAlign: 'center' as const,
    marginBottom: '24px',
  } as React.CSSProperties,

  loading: {
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'center',
    padding: '64px',
  } as React.CSSProperties,

  empty: {
    textAlign: 'center' as const,
    padding: '64px',
    color: 'rgba(255,255,255,0.5)',
    fontSize: '16px',
  } as React.CSSProperties,
};

// ============================================================================
// Helper Components
// ============================================================================

function CheckIcon(): JSX.Element {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <polyline points="20 6 9 17 4 12" />
    </svg>
  );
}

function LoadingSpinner(): JSX.Element {
  return (
    <svg
      width="32"
      height="32"
      viewBox="0 0 24 24"
      fill="none"
      style={{ animation: 'zalt-spin 1s linear infinite' }}
    >
      <style>{`@keyframes zalt-spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }`}</style>
      <circle
        cx="12"
        cy="12"
        r="10"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeDasharray="50"
        strokeDashoffset="15"
        opacity="0.3"
      />
    </svg>
  );
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Format price for display
 */
function formatPrice(priceInCents: number, currency: string = 'usd'): string {
  const amount = priceInCents / 100;
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: currency.toUpperCase(),
    minimumFractionDigits: 0,
    maximumFractionDigits: 2,
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
 * Format limit value for display
 */
function formatLimitValue(key: string, value: number): string {
  if (value === -1 || value === Number.MAX_SAFE_INTEGER) return 'Unlimited';
  
  // Format based on key type
  if (key.includes('storage') || key.includes('gb')) {
    return `${value} GB`;
  }
  if (key.includes('users') || key.includes('seats')) {
    return `${value} users`;
  }
  
  return value.toLocaleString();
}

/**
 * Format limit key for display
 */
function formatLimitKey(key: string): string {
  return key
    .replace(/_/g, ' ')
    .replace(/\b\w/g, l => l.toUpperCase());
}

// ============================================================================
// Main Component
// ============================================================================

/**
 * PricingTable component for displaying and selecting billing plans
 * 
 * @example
 * ```tsx
 * import { PricingTable } from '@zalt/react';
 * 
 * function PricingPage() {
 *   return (
 *     <PricingTable
 *       realmId="your-realm-id"
 *       tenantId="your-tenant-id"
 *       accessToken={token}
 *       currentPlanId={currentPlan?.id}
 *       onSubscribe={async (planId, interval) => {
 *         // Handle subscription with Stripe
 *       }}
 *       onSubscribeSuccess={(result) => {
 *         console.log('Subscribed:', result);
 *       }}
 *     />
 *   );
 * }
 * ```
 */
export function PricingTable({
  realmId,
  apiUrl = 'https://api.zalt.io',
  accessToken,
  tenantId,
  currentPlanId,
  defaultInterval = 'monthly',
  showIntervalToggle = true,
  showFeatures = true,
  maxFeaturesShown = 6,
  className = '',
  onSubscribe,
  onSubscribeSuccess,
  onError,
  subscribeButtonText = 'Get Started',
  currentPlanButtonText = 'Current Plan',
  upgradeButtonText = 'Upgrade',
  downgradeButtonText = 'Downgrade',
  showContactSales = true,
  onContactSales,
  compact = false,
  highlightRecommended = true,
  plans: providedPlans,
  currency: currencyOverride,
}: PricingTableProps): JSX.Element {
  // State
  const [plans, setPlans] = useState<BillingPlan[]>(providedPlans || []);
  const [interval, setInterval] = useState<BillingInterval>(defaultInterval);
  const [isLoading, setIsLoading] = useState(!providedPlans);
  const [error, setError] = useState<string | null>(null);
  const [subscribingPlanId, setSubscribingPlanId] = useState<string | null>(null);

  /**
   * Fetch plans from API
   */
  const fetchPlans = useCallback(async () => {
    if (providedPlans) return;

    setIsLoading(true);
    setError(null);

    try {
      const response = await fetch(`${apiUrl}/billing/plans?realm_id=${realmId}`, {
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
      
      // Filter active plans and sort by sort_order
      const activePlans = fetchedPlans
        .filter((p: BillingPlan) => p.status === 'active')
        .sort((a: BillingPlan, b: BillingPlan) => {
          const orderA = a.sort_order ?? Number.MAX_SAFE_INTEGER;
          const orderB = b.sort_order ?? Number.MAX_SAFE_INTEGER;
          return orderA - orderB;
        });

      setPlans(activePlans);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to fetch plans';
      setError(errorMessage);
      onError?.(err instanceof Error ? err : new Error(errorMessage));
    } finally {
      setIsLoading(false);
    }
  }, [apiUrl, realmId, accessToken, providedPlans, onError]);

  /**
   * Handle subscribe click
   */
  const handleSubscribe = useCallback(async (planId: string) => {
    if (subscribingPlanId) return;

    setSubscribingPlanId(planId);
    setError(null);

    try {
      if (onSubscribe) {
        await onSubscribe(planId, interval);
      } else if (accessToken && tenantId) {
        // Default subscription flow
        const response = await fetch(`${apiUrl}/billing/subscribe`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            tenant_id: tenantId,
            plan_id: planId,
            interval
          })
        });

        if (!response.ok) {
          const errorData = await response.json();
          throw new Error(errorData.error?.message || 'Failed to subscribe');
        }

        const data = await response.json();
        onSubscribeSuccess?.(data.data || data);
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to subscribe';
      setError(errorMessage);
      onError?.(err instanceof Error ? err : new Error(errorMessage));
    } finally {
      setSubscribingPlanId(null);
    }
  }, [apiUrl, accessToken, tenantId, interval, onSubscribe, onSubscribeSuccess, onError, subscribingPlanId]);

  /**
   * Get button text based on plan comparison
   */
  const getButtonText = useCallback((plan: BillingPlan): string => {
    if (plan.id === currentPlanId) {
      return currentPlanButtonText;
    }

    if (!currentPlanId) {
      return subscribeButtonText;
    }

    // Compare prices to determine upgrade/downgrade
    const currentPlan = plans.find(p => p.id === currentPlanId);
    if (!currentPlan) {
      return subscribeButtonText;
    }

    const currentPrice = interval === 'monthly' ? currentPlan.price_monthly : currentPlan.price_yearly;
    const planPrice = interval === 'monthly' ? plan.price_monthly : plan.price_yearly;

    if (planPrice > currentPrice) {
      return upgradeButtonText;
    } else if (planPrice < currentPrice) {
      return downgradeButtonText;
    }

    return subscribeButtonText;
  }, [currentPlanId, plans, interval, subscribeButtonText, currentPlanButtonText, upgradeButtonText, downgradeButtonText]);

  /**
   * Check if any plan has yearly savings
   */
  const hasYearlySavings = useMemo(() => {
    return plans.some(p => calculateYearlySavings(p.price_monthly, p.price_yearly) > 0);
  }, [plans]);

  /**
   * Get max yearly savings
   */
  const maxYearlySavings = useMemo(() => {
    return Math.max(...plans.map(p => calculateYearlySavings(p.price_monthly, p.price_yearly)), 0);
  }, [plans]);

  // Fetch plans on mount
  useEffect(() => {
    fetchPlans();
  }, [fetchPlans]);

  // Update plans if provided externally
  useEffect(() => {
    if (providedPlans) {
      setPlans(providedPlans);
    }
  }, [providedPlans]);

  // Loading state
  if (isLoading) {
    return (
      <div className={`zalt-pricing-table ${className}`} style={styles.container}>
        <div style={styles.loading}>
          <LoadingSpinner />
        </div>
      </div>
    );
  }

  // Empty state
  if (plans.length === 0) {
    return (
      <div className={`zalt-pricing-table ${className}`} style={styles.container}>
        <div style={styles.empty}>
          No pricing plans available.
        </div>
      </div>
    );
  }

  return (
    <div className={`zalt-pricing-table ${className}`} style={styles.container}>
      {/* Error display */}
      {error && (
        <div style={styles.error} role="alert">
          {error}
        </div>
      )}

      {/* Interval toggle */}
      {showIntervalToggle && hasYearlySavings && (
        <div style={styles.header}>
          <div style={styles.intervalToggle} role="tablist" aria-label="Billing interval">
            <button
              role="tab"
              aria-selected={interval === 'monthly'}
              onClick={() => setInterval('monthly')}
              style={{
                ...styles.intervalButton,
                ...(interval === 'monthly' ? styles.intervalButtonActive : {})
              }}
            >
              Monthly
            </button>
            <button
              role="tab"
              aria-selected={interval === 'yearly'}
              onClick={() => setInterval('yearly')}
              style={{
                ...styles.intervalButton,
                ...(interval === 'yearly' ? styles.intervalButtonActive : {})
              }}
            >
              Yearly
              {maxYearlySavings > 0 && (
                <span style={styles.savingsBadge}>
                  Save {maxYearlySavings}%
                </span>
              )}
            </button>
          </div>
        </div>
      )}

      {/* Plans grid */}
      <div style={styles.grid} role="list">
        {plans.map((plan) => {
          const isCurrentPlan = plan.id === currentPlanId;
          const isHighlighted = highlightRecommended && plan.highlight_text;
          const price = interval === 'monthly' ? plan.price_monthly : plan.price_yearly;
          const yearlySavings = calculateYearlySavings(plan.price_monthly, plan.price_yearly);
          const currency = currencyOverride || plan.currency;
          const isSubscribing = subscribingPlanId === plan.id;

          return (
            <div
              key={plan.id}
              role="listitem"
              style={{
                ...styles.card,
                ...(isHighlighted ? styles.cardHighlighted : {}),
                ...(isCurrentPlan ? styles.cardCurrent : {}),
                ...(compact ? { padding: '16px' } : {})
              }}
              data-plan-id={plan.id}
              data-highlighted={isHighlighted ? 'true' : undefined}
              data-current={isCurrentPlan ? 'true' : undefined}
            >
              {/* Highlight badge */}
              {isHighlighted && (
                <div style={styles.highlightBadge}>
                  {plan.highlight_text}
                </div>
              )}

              {/* Plan name */}
              <h3 style={styles.planName}>{plan.name}</h3>

              {/* Plan description */}
              {plan.description && !compact && (
                <p style={styles.planDescription}>{plan.description}</p>
              )}

              {/* Price */}
              <div style={styles.priceContainer}>
                {price === 0 ? (
                  <div style={styles.price}>Free</div>
                ) : (
                  <>
                    <div style={styles.price}>
                      <span style={styles.priceCurrency}>
                        {formatPrice(price, currency).charAt(0)}
                      </span>
                      {formatPrice(price, currency).slice(1).replace(/\.00$/, '')}
                      <span style={styles.priceInterval}>
                        /{interval === 'monthly' ? 'mo' : 'yr'}
                      </span>
                    </div>
                    {interval === 'yearly' && yearlySavings > 0 && (
                      <div style={styles.originalPrice}>
                        {formatPrice(plan.price_monthly * 12, currency)}/yr
                      </div>
                    )}
                  </>
                )}

                {/* Trial badge */}
                {plan.trial_days && plan.trial_days > 0 && !isCurrentPlan && (
                  <div style={styles.trialBadge}>
                    {plan.trial_days}-day free trial
                  </div>
                )}
              </div>

              {/* Features */}
              {showFeatures && plan.features.length > 0 && (
                <div style={styles.features}>
                  <div style={styles.featuresTitle}>What's included</div>
                  <ul style={styles.featureList}>
                    {plan.features.slice(0, maxFeaturesShown).map((feature, index) => (
                      <li key={index} style={styles.featureItem}>
                        <span style={styles.featureIcon}>
                          <CheckIcon />
                        </span>
                        <span>{feature}</span>
                      </li>
                    ))}
                  </ul>
                  {plan.features.length > maxFeaturesShown && (
                    <div style={styles.moreFeatures}>
                      +{plan.features.length - maxFeaturesShown} more features
                    </div>
                  )}
                </div>
              )}

              {/* Limits */}
              {!compact && Object.keys(plan.limits).length > 0 && (
                <div style={styles.limits}>
                  {Object.entries(plan.limits).slice(0, 4).map(([key, value]) => (
                    <div key={key} style={styles.limitItem}>
                      <span>{formatLimitKey(key)}</span>
                      <span style={styles.limitValue}>{formatLimitValue(key, value)}</span>
                    </div>
                  ))}
                </div>
              )}

              {/* Subscribe button */}
              <button
                onClick={() => !isCurrentPlan && handleSubscribe(plan.id)}
                disabled={isCurrentPlan || isSubscribing}
                style={{
                  ...styles.button,
                  ...(isCurrentPlan ? styles.buttonCurrent : {}),
                  ...(isSubscribing ? styles.buttonDisabled : {}),
                  ...(isHighlighted ? {} : styles.buttonSecondary)
                }}
                aria-label={`${getButtonText(plan)} - ${plan.name}`}
              >
                {isSubscribing ? (
                  <span style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px' }}>
                    <LoadingSpinner />
                    Processing...
                  </span>
                ) : (
                  getButtonText(plan)
                )}
              </button>
            </div>
          );
        })}
      </div>

      {/* Contact sales */}
      {showContactSales && onContactSales && (
        <div style={{ textAlign: 'center', marginTop: '32px' }}>
          <p style={{ color: 'rgba(255,255,255,0.6)', marginBottom: '12px' }}>
            Need a custom plan for your enterprise?
          </p>
          <button
            onClick={onContactSales}
            style={{
              ...styles.button,
              ...styles.buttonSecondary,
              width: 'auto',
              padding: '12px 32px'
            }}
          >
            Contact Sales
          </button>
        </div>
      )}
    </div>
  );
}

export default PricingTable;
