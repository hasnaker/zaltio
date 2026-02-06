/**
 * BillingPortal Component
 * @zalt/react
 * 
 * Component for managing billing subscriptions.
 * Shows current subscription info, payment methods, invoice history,
 * and allows canceling subscriptions.
 * 
 * Security Requirements:
 * - Mask sensitive payment info (show last 4 digits only)
 * - Input validation on all user inputs
 * - Error messages don't leak information
 * 
 * Validates: Requirement 7.8
 */

'use client';

import React, { useState, useCallback, useEffect, useMemo } from 'react';

// ============================================================================
// Types
// ============================================================================

/**
 * Subscription status
 */
export type SubscriptionStatus = 'active' | 'past_due' | 'canceled' | 'trialing';

/**
 * Billing interval
 */
export type BillingInterval = 'monthly' | 'yearly';

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
 * Billing plan from API
 */
export interface BillingPlan {
  id: string;
  realm_id: string;
  name: string;
  description?: string;
  type: 'per_user' | 'per_org' | 'flat_rate' | 'usage_based';
  price_monthly: number;
  price_yearly: number;
  currency: string;
  features: string[];
  limits: Record<string, number>;
  status: 'active' | 'inactive' | 'archived';
  trial_days?: number;
  created_at: string;
}

/**
 * Payment method from API (masked for security)
 */
export interface PaymentMethod {
  id: string;
  type: 'card' | 'bank_account' | 'other';
  brand?: string;
  last4: string;
  exp_month?: number;
  exp_year?: number;
  is_default: boolean;
}

/**
 * Invoice from API
 */
export interface Invoice {
  id: string;
  number?: string;
  status: 'draft' | 'open' | 'paid' | 'void' | 'uncollectible';
  amount_due: number;
  amount_paid: number;
  currency: string;
  period_start: string;
  period_end: string;
  invoice_pdf?: string;
  hosted_invoice_url?: string;
  created_at: string;
}

/**
 * BillingPortal props
 */
export interface BillingPortalProps {
  /** API base URL */
  apiUrl?: string;
  /** Access token for authenticated requests */
  accessToken?: string;
  /** Tenant ID for billing operations */
  tenantId?: string;
  /** Realm ID for fetching plan details */
  realmId?: string;
  /** Custom class name */
  className?: string;
  /** Show payment methods section */
  showPaymentMethods?: boolean;
  /** Show invoice history section */
  showInvoices?: boolean;
  /** Maximum invoices to show */
  maxInvoicesShown?: number;
  /** Callback when subscription is canceled */
  onCancelSubscription?: (subscriptionId: string, cancelAtPeriodEnd: boolean) => Promise<void>;
  /** Callback when cancel succeeds */
  onCancelSuccess?: () => void;
  /** Callback when payment method is updated */
  onUpdatePaymentMethod?: () => void;
  /** Callback on error */
  onError?: (error: Error) => void;
  /** Custom cancel button text */
  cancelButtonText?: string;
  /** Custom reactivate button text */
  reactivateButtonText?: string;
  /** Show upgrade/change plan button */
  showChangePlan?: boolean;
  /** Callback when user wants to change plan */
  onChangePlan?: () => void;
  /** Stripe publishable key for payment method updates */
  stripePublishableKey?: string;
  /** Compact mode */
  compact?: boolean;
  /** Pre-loaded subscription (skip API fetch) */
  subscription?: Subscription;
  /** Pre-loaded plan (skip API fetch) */
  plan?: BillingPlan;
}


// ============================================================================
// Styles
// ============================================================================

const styles = {
  container: {
    fontFamily: 'var(--zalt-font, system-ui, sans-serif)',
    color: 'var(--zalt-text, #fff)',
    maxWidth: '800px',
    margin: '0 auto',
    padding: '24px',
  } as React.CSSProperties,

  section: {
    background: 'rgba(255,255,255,0.05)',
    borderRadius: 'var(--zalt-radius, 0.75rem)',
    padding: '24px',
    marginBottom: '24px',
    border: '1px solid rgba(255,255,255,0.1)',
  } as React.CSSProperties,

  sectionTitle: {
    fontSize: '18px',
    fontWeight: 600,
    margin: '0 0 16px 0',
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
  } as React.CSSProperties,

  subscriptionHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    flexWrap: 'wrap' as const,
    gap: '16px',
  } as React.CSSProperties,

  planInfo: {
    flex: 1,
    minWidth: '200px',
  } as React.CSSProperties,

  planName: {
    fontSize: '24px',
    fontWeight: 700,
    margin: '0 0 4px 0',
  } as React.CSSProperties,

  planPrice: {
    fontSize: '16px',
    color: 'rgba(255,255,255,0.7)',
    margin: '0 0 8px 0',
  } as React.CSSProperties,

  statusBadge: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: '6px',
    padding: '6px 12px',
    borderRadius: '9999px',
    fontSize: '13px',
    fontWeight: 600,
  } as React.CSSProperties,

  statusActive: {
    background: 'rgba(16, 185, 129, 0.2)',
    color: '#10b981',
  } as React.CSSProperties,

  statusTrialing: {
    background: 'rgba(59, 130, 246, 0.2)',
    color: '#3b82f6',
  } as React.CSSProperties,

  statusPastDue: {
    background: 'rgba(245, 158, 11, 0.2)',
    color: '#f59e0b',
  } as React.CSSProperties,

  statusCanceled: {
    background: 'rgba(239, 68, 68, 0.2)',
    color: '#ef4444',
  } as React.CSSProperties,


  periodInfo: {
    marginTop: '16px',
    padding: '12px 16px',
    background: 'rgba(255,255,255,0.03)',
    borderRadius: 'var(--zalt-radius, 0.5rem)',
    fontSize: '14px',
    color: 'rgba(255,255,255,0.7)',
  } as React.CSSProperties,

  periodLabel: {
    fontWeight: 500,
    color: 'rgba(255,255,255,0.5)',
    marginBottom: '4px',
  } as React.CSSProperties,

  cancelWarning: {
    marginTop: '16px',
    padding: '12px 16px',
    background: 'rgba(245, 158, 11, 0.1)',
    border: '1px solid rgba(245, 158, 11, 0.3)',
    borderRadius: 'var(--zalt-radius, 0.5rem)',
    fontSize: '14px',
    color: '#f59e0b',
  } as React.CSSProperties,

  actions: {
    display: 'flex',
    gap: '12px',
    marginTop: '20px',
    flexWrap: 'wrap' as const,
  } as React.CSSProperties,

  button: {
    padding: '12px 20px',
    border: 'none',
    borderRadius: 'var(--zalt-radius, 0.5rem)',
    fontSize: '14px',
    fontWeight: 600,
    cursor: 'pointer',
    transition: 'opacity 0.15s, transform 0.1s',
  } as React.CSSProperties,

  buttonPrimary: {
    background: 'var(--zalt-primary, #10b981)',
    color: '#000',
  } as React.CSSProperties,

  buttonSecondary: {
    background: 'transparent',
    color: 'var(--zalt-primary, #10b981)',
    border: '2px solid var(--zalt-primary, #10b981)',
  } as React.CSSProperties,

  buttonDanger: {
    background: 'transparent',
    color: '#ef4444',
    border: '2px solid #ef4444',
  } as React.CSSProperties,

  buttonDisabled: {
    opacity: 0.6,
    cursor: 'not-allowed',
  } as React.CSSProperties,

  paymentMethod: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '16px',
    background: 'rgba(255,255,255,0.03)',
    borderRadius: 'var(--zalt-radius, 0.5rem)',
    marginBottom: '12px',
  } as React.CSSProperties,

  paymentMethodInfo: {
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
  } as React.CSSProperties,

  cardIcon: {
    width: '40px',
    height: '28px',
    background: 'rgba(255,255,255,0.1)',
    borderRadius: '4px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    fontSize: '12px',
    fontWeight: 600,
  } as React.CSSProperties,


  cardDetails: {
    display: 'flex',
    flexDirection: 'column' as const,
    gap: '2px',
  } as React.CSSProperties,

  cardNumber: {
    fontSize: '14px',
    fontWeight: 500,
  } as React.CSSProperties,

  cardExpiry: {
    fontSize: '12px',
    color: 'rgba(255,255,255,0.5)',
  } as React.CSSProperties,

  defaultBadge: {
    padding: '2px 8px',
    background: 'rgba(16, 185, 129, 0.2)',
    color: '#10b981',
    borderRadius: '4px',
    fontSize: '11px',
    fontWeight: 600,
    textTransform: 'uppercase' as const,
  } as React.CSSProperties,

  invoiceTable: {
    width: '100%',
    borderCollapse: 'collapse' as const,
  } as React.CSSProperties,

  invoiceHeader: {
    textAlign: 'left' as const,
    padding: '12px 8px',
    fontSize: '12px',
    fontWeight: 600,
    color: 'rgba(255,255,255,0.5)',
    textTransform: 'uppercase' as const,
    letterSpacing: '0.5px',
    borderBottom: '1px solid rgba(255,255,255,0.1)',
  } as React.CSSProperties,

  invoiceRow: {
    borderBottom: '1px solid rgba(255,255,255,0.05)',
  } as React.CSSProperties,

  invoiceCell: {
    padding: '12px 8px',
    fontSize: '14px',
    color: 'rgba(255,255,255,0.8)',
  } as React.CSSProperties,

  invoiceStatus: {
    display: 'inline-block',
    padding: '2px 8px',
    borderRadius: '4px',
    fontSize: '12px',
    fontWeight: 500,
  } as React.CSSProperties,

  invoiceStatusPaid: {
    background: 'rgba(16, 185, 129, 0.2)',
    color: '#10b981',
  } as React.CSSProperties,

  invoiceStatusOpen: {
    background: 'rgba(59, 130, 246, 0.2)',
    color: '#3b82f6',
  } as React.CSSProperties,

  invoiceStatusVoid: {
    background: 'rgba(107, 114, 128, 0.2)',
    color: '#6b7280',
  } as React.CSSProperties,

  invoiceLink: {
    color: 'var(--zalt-primary, #10b981)',
    textDecoration: 'none',
    fontSize: '13px',
    fontWeight: 500,
  } as React.CSSProperties,

  error: {
    padding: '16px',
    background: 'rgba(239, 68, 68, 0.1)',
    border: '1px solid rgba(239, 68, 68, 0.3)',
    borderRadius: 'var(--zalt-radius, 0.5rem)',
    color: '#ef4444',
    fontSize: '14px',
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
    padding: '48px',
    color: 'rgba(255,255,255,0.5)',
  } as React.CSSProperties,

  emptyTitle: {
    fontSize: '18px',
    fontWeight: 600,
    marginBottom: '8px',
    color: 'rgba(255,255,255,0.8)',
  } as React.CSSProperties,

  emptyDescription: {
    fontSize: '14px',
    marginBottom: '20px',
  } as React.CSSProperties,

  modal: {
    position: 'fixed' as const,
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    background: 'rgba(0,0,0,0.8)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    zIndex: 1000,
  } as React.CSSProperties,

  modalContent: {
    background: '#1a1a1a',
    borderRadius: 'var(--zalt-radius, 0.75rem)',
    padding: '24px',
    maxWidth: '400px',
    width: '90%',
    border: '1px solid rgba(255,255,255,0.1)',
  } as React.CSSProperties,

  modalTitle: {
    fontSize: '18px',
    fontWeight: 600,
    marginBottom: '12px',
  } as React.CSSProperties,

  modalText: {
    fontSize: '14px',
    color: 'rgba(255,255,255,0.7)',
    marginBottom: '20px',
    lineHeight: 1.5,
  } as React.CSSProperties,

  modalActions: {
    display: 'flex',
    gap: '12px',
    justifyContent: 'flex-end',
  } as React.CSSProperties,
};


// ============================================================================
// Helper Components
// ============================================================================

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

function StatusDot(): JSX.Element {
  return (
    <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: 'currentColor' }} />
  );
}

function CardBrandIcon({ brand }: { brand?: string }): JSX.Element {
  const brandText = brand?.toUpperCase().slice(0, 4) || 'CARD';
  return <span>{brandText}</span>;
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
 * Format date for display
 */
function formatDate(dateString: string): string {
  const date = new Date(dateString);
  return date.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
}

/**
 * Get days remaining until date
 */
function getDaysUntil(dateString: string): number {
  const now = new Date();
  const target = new Date(dateString);
  const diffMs = target.getTime() - now.getTime();
  return Math.max(0, Math.ceil(diffMs / (1000 * 60 * 60 * 24)));
}

/**
 * Get status badge style
 */
function getStatusStyle(status: SubscriptionStatus): React.CSSProperties {
  switch (status) {
    case 'active':
      return { ...styles.statusBadge, ...styles.statusActive };
    case 'trialing':
      return { ...styles.statusBadge, ...styles.statusTrialing };
    case 'past_due':
      return { ...styles.statusBadge, ...styles.statusPastDue };
    case 'canceled':
      return { ...styles.statusBadge, ...styles.statusCanceled };
    default:
      return styles.statusBadge;
  }
}

/**
 * Format status for display
 */
function formatStatus(status: SubscriptionStatus): string {
  const statusMap: Record<SubscriptionStatus, string> = {
    active: 'Active',
    trialing: 'Trial',
    past_due: 'Past Due',
    canceled: 'Canceled',
  };
  return statusMap[status] || status;
}

/**
 * Get invoice status style
 */
function getInvoiceStatusStyle(status: Invoice['status']): React.CSSProperties {
  switch (status) {
    case 'paid':
      return { ...styles.invoiceStatus, ...styles.invoiceStatusPaid };
    case 'open':
    case 'draft':
      return { ...styles.invoiceStatus, ...styles.invoiceStatusOpen };
    default:
      return { ...styles.invoiceStatus, ...styles.invoiceStatusVoid };
  }
}

/**
 * Mask card number for security (show last 4 only)
 */
function maskCardNumber(last4: string): string {
  return `•••• •••• •••• ${last4}`;
}


// ============================================================================
// Cancel Confirmation Modal
// ============================================================================

interface CancelModalProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: (cancelAtPeriodEnd: boolean) => void;
  isLoading: boolean;
  periodEnd: string;
}

function CancelModal({ isOpen, onClose, onConfirm, isLoading, periodEnd }: CancelModalProps): JSX.Element | null {
  if (!isOpen) return null;

  return (
    <div style={styles.modal} onClick={onClose} role="dialog" aria-modal="true" aria-labelledby="cancel-modal-title">
      <div style={styles.modalContent} onClick={(e) => e.stopPropagation()}>
        <h3 id="cancel-modal-title" style={styles.modalTitle}>Cancel Subscription</h3>
        <p style={styles.modalText}>
          Are you sure you want to cancel your subscription? You will continue to have access until{' '}
          <strong>{formatDate(periodEnd)}</strong>.
        </p>
        <div style={styles.modalActions}>
          <button
            onClick={onClose}
            disabled={isLoading}
            style={{
              ...styles.button,
              ...styles.buttonSecondary,
              ...(isLoading ? styles.buttonDisabled : {}),
            }}
          >
            Keep Subscription
          </button>
          <button
            onClick={() => onConfirm(true)}
            disabled={isLoading}
            style={{
              ...styles.button,
              ...styles.buttonDanger,
              ...(isLoading ? styles.buttonDisabled : {}),
            }}
          >
            {isLoading ? 'Canceling...' : 'Cancel Subscription'}
          </button>
        </div>
      </div>
    </div>
  );
}


// ============================================================================
// Main Component
// ============================================================================

/**
 * BillingPortal component for managing subscriptions
 * 
 * @example
 * ```tsx
 * import { BillingPortal } from '@zalt/react';
 * 
 * function BillingPage() {
 *   return (
 *     <BillingPortal
 *       tenantId="your-tenant-id"
 *       accessToken={token}
 *       onCancelSuccess={() => {
 *         console.log('Subscription canceled');
 *       }}
 *       onChangePlan={() => {
 *         // Navigate to pricing page
 *       }}
 *     />
 *   );
 * }
 * ```
 */
export function BillingPortal({
  apiUrl = 'https://api.zalt.io',
  accessToken,
  tenantId,
  realmId,
  className = '',
  showPaymentMethods = true,
  showInvoices = true,
  maxInvoicesShown = 10,
  onCancelSubscription,
  onCancelSuccess,
  onUpdatePaymentMethod,
  onError,
  cancelButtonText = 'Cancel Subscription',
  reactivateButtonText = 'Reactivate',
  showChangePlan = true,
  onChangePlan,
  compact = false,
  subscription: providedSubscription,
  plan: providedPlan,
}: BillingPortalProps): JSX.Element {
  // State
  const [subscription, setSubscription] = useState<Subscription | null>(providedSubscription || null);
  const [plan, setPlan] = useState<BillingPlan | null>(providedPlan || null);
  const [paymentMethods, setPaymentMethods] = useState<PaymentMethod[]>([]);
  const [invoices, setInvoices] = useState<Invoice[]>([]);
  const [isLoading, setIsLoading] = useState(!providedSubscription);
  const [error, setError] = useState<string | null>(null);
  const [isCanceling, setIsCanceling] = useState(false);
  const [showCancelModal, setShowCancelModal] = useState(false);

  /**
   * Fetch subscription data
   */
  const fetchSubscription = useCallback(async () => {
    if (!tenantId || !accessToken) return;

    try {
      const response = await fetch(`${apiUrl}/billing/subscription?tenant_id=${tenantId}`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        if (response.status === 404) {
          setSubscription(null);
          return;
        }
        const errorData = await response.json();
        throw new Error(errorData.error?.message || 'Failed to fetch subscription');
      }

      const data = await response.json();
      setSubscription(data.data || data);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to fetch subscription';
      setError(errorMessage);
      onError?.(err instanceof Error ? err : new Error(errorMessage));
    }
  }, [apiUrl, accessToken, tenantId, onError]);


  /**
   * Fetch plan details
   */
  const fetchPlan = useCallback(async () => {
    if (!subscription || !realmId || !accessToken) return;

    try {
      const response = await fetch(
        `${apiUrl}/billing/plans/${subscription.plan_id}?realm_id=${realmId}`,
        {
          method: 'GET',
          headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Content-Type': 'application/json',
          },
        }
      );

      if (!response.ok) {
        // Plan fetch is optional, don't fail the whole component
        console.warn('Failed to fetch plan details');
        return;
      }

      const data = await response.json();
      setPlan(data.data || data);
    } catch (err) {
      console.warn('Failed to fetch plan:', err);
    }
  }, [apiUrl, accessToken, subscription, realmId]);

  /**
   * Fetch payment methods
   */
  const fetchPaymentMethods = useCallback(async () => {
    if (!tenantId || !accessToken || !showPaymentMethods) return;

    try {
      const response = await fetch(`${apiUrl}/billing/payment-methods?tenant_id=${tenantId}`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        // Payment methods fetch is optional
        return;
      }

      const data = await response.json();
      setPaymentMethods(data.data?.payment_methods || data.payment_methods || []);
    } catch (err) {
      console.warn('Failed to fetch payment methods:', err);
    }
  }, [apiUrl, accessToken, tenantId, showPaymentMethods]);

  /**
   * Fetch invoices
   */
  const fetchInvoices = useCallback(async () => {
    if (!tenantId || !accessToken || !showInvoices) return;

    try {
      const response = await fetch(
        `${apiUrl}/billing/invoices?tenant_id=${tenantId}&limit=${maxInvoicesShown}`,
        {
          method: 'GET',
          headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Content-Type': 'application/json',
          },
        }
      );

      if (!response.ok) {
        // Invoices fetch is optional
        return;
      }

      const data = await response.json();
      setInvoices(data.data?.invoices || data.invoices || []);
    } catch (err) {
      console.warn('Failed to fetch invoices:', err);
    }
  }, [apiUrl, accessToken, tenantId, showInvoices, maxInvoicesShown]);


  /**
   * Handle cancel subscription
   */
  const handleCancelSubscription = useCallback(async (cancelAtPeriodEnd: boolean) => {
    if (!subscription) return;

    setIsCanceling(true);
    setError(null);

    try {
      if (onCancelSubscription) {
        await onCancelSubscription(subscription.id, cancelAtPeriodEnd);
      } else if (accessToken) {
        const response = await fetch(`${apiUrl}/billing/cancel`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            subscription_id: subscription.id,
            tenant_id: subscription.tenant_id,
            cancel_at_period_end: cancelAtPeriodEnd,
          }),
        });

        if (!response.ok) {
          const errorData = await response.json();
          throw new Error(errorData.error?.message || 'Failed to cancel subscription');
        }
      }

      // Update local state
      if (cancelAtPeriodEnd) {
        setSubscription((prev) =>
          prev ? { ...prev, cancel_at_period_end: true } : null
        );
      } else {
        setSubscription((prev) =>
          prev
            ? { ...prev, status: 'canceled', canceled_at: new Date().toISOString() }
            : null
        );
      }

      setShowCancelModal(false);
      onCancelSuccess?.();
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to cancel subscription';
      setError(errorMessage);
      onError?.(err instanceof Error ? err : new Error(errorMessage));
    } finally {
      setIsCanceling(false);
    }
  }, [apiUrl, accessToken, subscription, onCancelSubscription, onCancelSuccess, onError]);

  /**
   * Computed values
   */
  const daysRemaining = useMemo(() => {
    if (!subscription) return 0;
    return getDaysUntil(subscription.current_period_end);
  }, [subscription]);

  const trialDaysRemaining = useMemo(() => {
    if (!subscription?.trial_end) return 0;
    return getDaysUntil(subscription.trial_end);
  }, [subscription]);

  const isTrialing = subscription?.status === 'trialing';
  const isCanceled = subscription?.status === 'canceled';
  const willCancel = subscription?.cancel_at_period_end === true;
  const isPastDue = subscription?.status === 'past_due';


  /**
   * Load data on mount
   */
  useEffect(() => {
    const loadData = async () => {
      if (providedSubscription) {
        setIsLoading(false);
        return;
      }

      setIsLoading(true);
      await fetchSubscription();
      setIsLoading(false);
    };

    loadData();
  }, [fetchSubscription, providedSubscription]);

  /**
   * Fetch plan when subscription changes
   */
  useEffect(() => {
    if (subscription && !providedPlan) {
      fetchPlan();
    }
  }, [subscription, fetchPlan, providedPlan]);

  /**
   * Fetch payment methods and invoices when subscription is loaded
   */
  useEffect(() => {
    if (subscription) {
      fetchPaymentMethods();
      fetchInvoices();
    }
  }, [subscription, fetchPaymentMethods, fetchInvoices]);

  /**
   * Update state when props change
   */
  useEffect(() => {
    if (providedSubscription) {
      setSubscription(providedSubscription);
    }
  }, [providedSubscription]);

  useEffect(() => {
    if (providedPlan) {
      setPlan(providedPlan);
    }
  }, [providedPlan]);

  // Loading state
  if (isLoading) {
    return (
      <div className={`zalt-billing-portal ${className}`} style={styles.container}>
        <div style={styles.loading}>
          <LoadingSpinner />
        </div>
      </div>
    );
  }

  // No subscription state
  if (!subscription) {
    return (
      <div className={`zalt-billing-portal ${className}`} style={styles.container}>
        <div style={styles.section}>
          <div style={styles.empty}>
            <div style={styles.emptyTitle}>No Active Subscription</div>
            <div style={styles.emptyDescription}>
              You don't have an active subscription. Choose a plan to get started.
            </div>
            {showChangePlan && onChangePlan && (
              <button
                onClick={onChangePlan}
                style={{ ...styles.button, ...styles.buttonPrimary }}
              >
                View Plans
              </button>
            )}
          </div>
        </div>
      </div>
    );
  }


  return (
    <div className={`zalt-billing-portal ${className}`} style={styles.container}>
      {/* Error display */}
      {error && (
        <div style={styles.error} role="alert">
          {error}
        </div>
      )}

      {/* Subscription Section */}
      <section style={styles.section} aria-labelledby="subscription-title">
        <h2 id="subscription-title" style={styles.sectionTitle}>
          Current Subscription
        </h2>

        <div style={styles.subscriptionHeader}>
          <div style={styles.planInfo}>
            <h3 style={styles.planName}>{plan?.name || 'Subscription'}</h3>
            {plan && (
              <p style={styles.planPrice}>
                {formatPrice(plan.price_monthly, plan.currency)}/month
              </p>
            )}
            <span style={getStatusStyle(subscription.status)}>
              <StatusDot />
              {formatStatus(subscription.status)}
            </span>
          </div>
        </div>

        {/* Trial info */}
        {isTrialing && trialDaysRemaining > 0 && (
          <div style={styles.periodInfo}>
            <div style={styles.periodLabel}>Trial Period</div>
            <div>
              {trialDaysRemaining} day{trialDaysRemaining !== 1 ? 's' : ''} remaining
              {subscription.trial_end && ` (ends ${formatDate(subscription.trial_end)})`}
            </div>
          </div>
        )}

        {/* Billing period info */}
        {!compact && (
          <div style={styles.periodInfo}>
            <div style={styles.periodLabel}>Current Billing Period</div>
            <div>
              {formatDate(subscription.current_period_start)} - {formatDate(subscription.current_period_end)}
              {!isCanceled && !willCancel && (
                <span style={{ marginLeft: '8px', color: 'rgba(255,255,255,0.5)' }}>
                  ({daysRemaining} day{daysRemaining !== 1 ? 's' : ''} remaining)
                </span>
              )}
            </div>
          </div>
        )}

        {/* Cancel warning */}
        {willCancel && !isCanceled && (
          <div style={styles.cancelWarning}>
            ⚠️ Your subscription will be canceled on {formatDate(subscription.current_period_end)}.
            You will continue to have access until then.
          </div>
        )}

        {/* Past due warning */}
        {isPastDue && (
          <div style={{ ...styles.cancelWarning, background: 'rgba(239, 68, 68, 0.1)', borderColor: 'rgba(239, 68, 68, 0.3)', color: '#ef4444' }}>
            ⚠️ Your payment is past due. Please update your payment method to avoid service interruption.
          </div>
        )}

        {/* Actions */}
        <div style={styles.actions}>
          {showChangePlan && onChangePlan && !isCanceled && (
            <button
              onClick={onChangePlan}
              style={{ ...styles.button, ...styles.buttonSecondary }}
            >
              Change Plan
            </button>
          )}

          {!isCanceled && !willCancel && (
            <button
              onClick={() => setShowCancelModal(true)}
              style={{ ...styles.button, ...styles.buttonDanger }}
            >
              {cancelButtonText}
            </button>
          )}

          {willCancel && !isCanceled && (
            <button
              onClick={() => handleCancelSubscription(false)}
              disabled={isCanceling}
              style={{
                ...styles.button,
                ...styles.buttonPrimary,
                ...(isCanceling ? styles.buttonDisabled : {}),
              }}
            >
              {isCanceling ? 'Processing...' : reactivateButtonText}
            </button>
          )}

          {isCanceled && showChangePlan && onChangePlan && (
            <button
              onClick={onChangePlan}
              style={{ ...styles.button, ...styles.buttonPrimary }}
            >
              Subscribe Again
            </button>
          )}
        </div>
      </section>


      {/* Payment Methods Section */}
      {showPaymentMethods && paymentMethods.length > 0 && (
        <section style={styles.section} aria-labelledby="payment-methods-title">
          <h2 id="payment-methods-title" style={styles.sectionTitle}>
            Payment Methods
          </h2>

          {paymentMethods.map((method) => (
            <div key={method.id} style={styles.paymentMethod}>
              <div style={styles.paymentMethodInfo}>
                <div style={styles.cardIcon}>
                  <CardBrandIcon brand={method.brand} />
                </div>
                <div style={styles.cardDetails}>
                  <div style={styles.cardNumber}>{maskCardNumber(method.last4)}</div>
                  {method.exp_month && method.exp_year && (
                    <div style={styles.cardExpiry}>
                      Expires {String(method.exp_month).padStart(2, '0')}/{method.exp_year}
                    </div>
                  )}
                </div>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                {method.is_default && (
                  <span style={styles.defaultBadge}>Default</span>
                )}
                {onUpdatePaymentMethod && (
                  <button
                    onClick={onUpdatePaymentMethod}
                    style={{
                      ...styles.button,
                      ...styles.buttonSecondary,
                      padding: '8px 16px',
                      fontSize: '13px',
                    }}
                  >
                    Update
                  </button>
                )}
              </div>
            </div>
          ))}

          {paymentMethods.length === 0 && (
            <div style={{ color: 'rgba(255,255,255,0.5)', fontSize: '14px' }}>
              No payment methods on file.
            </div>
          )}
        </section>
      )}

      {/* Invoice History Section */}
      {showInvoices && invoices.length > 0 && (
        <section style={styles.section} aria-labelledby="invoices-title">
          <h2 id="invoices-title" style={styles.sectionTitle}>
            Invoice History
          </h2>

          <table style={styles.invoiceTable}>
            <thead>
              <tr>
                <th style={styles.invoiceHeader}>Date</th>
                <th style={styles.invoiceHeader}>Amount</th>
                <th style={styles.invoiceHeader}>Status</th>
                <th style={styles.invoiceHeader}></th>
              </tr>
            </thead>
            <tbody>
              {invoices.map((invoice) => (
                <tr key={invoice.id} style={styles.invoiceRow}>
                  <td style={styles.invoiceCell}>{formatDate(invoice.created_at)}</td>
                  <td style={styles.invoiceCell}>
                    {formatPrice(invoice.amount_due, invoice.currency)}
                  </td>
                  <td style={styles.invoiceCell}>
                    <span style={getInvoiceStatusStyle(invoice.status)}>
                      {invoice.status.charAt(0).toUpperCase() + invoice.status.slice(1)}
                    </span>
                  </td>
                  <td style={{ ...styles.invoiceCell, textAlign: 'right' }}>
                    {invoice.invoice_pdf && (
                      <a
                        href={invoice.invoice_pdf}
                        target="_blank"
                        rel="noopener noreferrer"
                        style={styles.invoiceLink}
                      >
                        Download
                      </a>
                    )}
                    {invoice.hosted_invoice_url && !invoice.invoice_pdf && (
                      <a
                        href={invoice.hosted_invoice_url}
                        target="_blank"
                        rel="noopener noreferrer"
                        style={styles.invoiceLink}
                      >
                        View
                      </a>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      {/* Cancel Modal */}
      <CancelModal
        isOpen={showCancelModal}
        onClose={() => setShowCancelModal(false)}
        onConfirm={handleCancelSubscription}
        isLoading={isCanceling}
        periodEnd={subscription.current_period_end}
      />
    </div>
  );
}

export default BillingPortal;
