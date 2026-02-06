/**
 * PricingTable Component Tests
 * 
 * Validates: Requirement 7.7 (SDK PricingTable component)
 * 
 * Tests:
 * - Render pricing plans
 * - Plan comparison display
 * - Interval toggle (monthly/yearly)
 * - Subscribe action
 * - Current plan indication
 * - Loading and error states
 * - Feature display
 * - Accessibility
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react';
import React from 'react';
import { PricingTable, type BillingPlan } from '../PricingTable';

// Mock fetch globally
const mockFetch = vi.fn();
global.fetch = mockFetch;

// Sample plans for testing
const samplePlans: BillingPlan[] = [
  {
    id: 'plan_free',
    realm_id: 'test-realm',
    name: 'Free',
    description: 'Perfect for getting started',
    type: 'flat_rate',
    price_monthly: 0,
    price_yearly: 0,
    currency: 'usd',
    features: ['5 users', 'Basic support', '1 GB storage'],
    limits: { users: 5, storage_gb: 1 },
    status: 'active',
    sort_order: 1,
    created_at: '2024-01-01T00:00:00Z'
  },
  {
    id: 'plan_pro',
    realm_id: 'test-realm',
    name: 'Pro',
    description: 'For growing teams',
    type: 'per_user',
    price_monthly: 2900, // $29/mo
    price_yearly: 29000, // $290/yr (save ~17%)
    currency: 'usd',
    features: ['Unlimited users', 'Priority support', '100 GB storage', 'Advanced analytics', 'API access', 'Custom integrations', 'SSO'],
    limits: { users: -1, storage_gb: 100 },
    status: 'active',
    sort_order: 2,
    highlight_text: 'Most Popular',
    trial_days: 14,
    created_at: '2024-01-01T00:00:00Z'
  },
  {
    id: 'plan_enterprise',
    realm_id: 'test-realm',
    name: 'Enterprise',
    description: 'For large organizations',
    type: 'flat_rate',
    price_monthly: 9900, // $99/mo
    price_yearly: 99000, // $990/yr (save ~17%)
    currency: 'usd',
    features: ['Everything in Pro', 'Dedicated support', 'Unlimited storage', 'Custom contracts', 'SLA guarantee'],
    limits: { users: -1, storage_gb: -1 },
    status: 'active',
    sort_order: 3,
    created_at: '2024-01-01T00:00:00Z'
  }
];

describe('PricingTable Component', () => {
  const defaultProps = {
    realmId: 'test-realm-123',
    apiUrl: 'https://api.zalt.io',
  };

  beforeEach(() => {
    vi.clearAllMocks();
    mockFetch.mockReset();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Rendering', () => {
    it('should render loading state initially', () => {
      mockFetch.mockReturnValueOnce(new Promise(() => {})); // Never resolves

      render(<PricingTable {...defaultProps} />);

      // Should show loading spinner
      expect(document.querySelector('.zalt-pricing-table')).toBeTruthy();
    });

    it('should render plans from API', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ data: { plans: samplePlans } })
      });

      render(<PricingTable {...defaultProps} />);

      await waitFor(() => {
        // Use heading role to find plan names specifically
        expect(screen.getByRole('heading', { name: 'Free' })).toBeTruthy();
        expect(screen.getByRole('heading', { name: 'Pro' })).toBeTruthy();
        expect(screen.getByRole('heading', { name: 'Enterprise' })).toBeTruthy();
      });
    });

    it('should render plans provided via props', () => {
      render(<PricingTable {...defaultProps} plans={samplePlans} />);

      // Use heading role to find plan names specifically
      expect(screen.getByRole('heading', { name: 'Free' })).toBeTruthy();
      expect(screen.getByRole('heading', { name: 'Pro' })).toBeTruthy();
      expect(screen.getByRole('heading', { name: 'Enterprise' })).toBeTruthy();
    });

    it('should render plan descriptions', () => {
      render(<PricingTable {...defaultProps} plans={samplePlans} />);

      expect(screen.getByText('Perfect for getting started')).toBeTruthy();
      expect(screen.getByText('For growing teams')).toBeTruthy();
      expect(screen.getByText('For large organizations')).toBeTruthy();
    });

    it('should render empty state when no plans', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ data: { plans: [] } })
      });

      render(<PricingTable {...defaultProps} />);

      await waitFor(() => {
        expect(screen.getByText('No pricing plans available.')).toBeTruthy();
      });
    });

    it('should apply custom className', () => {
      const { container } = render(
        <PricingTable {...defaultProps} plans={samplePlans} className="custom-pricing" />
      );

      expect(container.querySelector('.custom-pricing')).toBeTruthy();
    });
  });

  describe('Pricing Display', () => {
    it('should display monthly prices by default', () => {
      render(<PricingTable {...defaultProps} plans={samplePlans} />);

      // Free plan shows "Free" as price - check that plan exists via heading
      expect(screen.getByRole('heading', { name: 'Free' })).toBeTruthy();
      
      // Pro plan shows $29
      expect(screen.getByText(/29/)).toBeTruthy();
      
      // Enterprise shows $99
      expect(screen.getByText(/99/)).toBeTruthy();
    });

    it('should display yearly prices when interval is yearly', () => {
      render(<PricingTable {...defaultProps} plans={samplePlans} defaultInterval="yearly" />);

      // Pro plan shows $290
      expect(screen.getByText(/290/)).toBeTruthy();
      
      // Enterprise shows $990
      expect(screen.getByText(/990/)).toBeTruthy();
    });

    it('should show interval suffix', () => {
      render(<PricingTable {...defaultProps} plans={samplePlans} />);

      // Should show /mo for monthly
      const moElements = screen.getAllByText(/\/mo/);
      expect(moElements.length).toBeGreaterThan(0);
    });
  });

  describe('Interval Toggle', () => {
    it('should render interval toggle when plans have yearly savings', () => {
      render(<PricingTable {...defaultProps} plans={samplePlans} />);

      expect(screen.getByRole('tab', { name: /monthly/i })).toBeTruthy();
      expect(screen.getByRole('tab', { name: /yearly/i })).toBeTruthy();
    });

    it('should switch to yearly pricing when yearly tab clicked', async () => {
      render(<PricingTable {...defaultProps} plans={samplePlans} />);

      const yearlyTab = screen.getByRole('tab', { name: /yearly/i });
      fireEvent.click(yearlyTab);

      await waitFor(() => {
        // Should show /yr suffix
        const yrElements = screen.getAllByText(/\/yr/);
        expect(yrElements.length).toBeGreaterThan(0);
      });
    });

    it('should show savings badge on yearly tab', () => {
      render(<PricingTable {...defaultProps} plans={samplePlans} />);

      // Should show "Save X%" badge
      expect(screen.getByText(/save/i)).toBeTruthy();
    });

    it('should hide interval toggle when showIntervalToggle is false', () => {
      render(<PricingTable {...defaultProps} plans={samplePlans} showIntervalToggle={false} />);

      expect(screen.queryByRole('tab', { name: /monthly/i })).toBeNull();
      expect(screen.queryByRole('tab', { name: /yearly/i })).toBeNull();
    });

    it('should mark active interval tab as selected', () => {
      render(<PricingTable {...defaultProps} plans={samplePlans} />);

      const monthlyTab = screen.getByRole('tab', { name: /monthly/i });
      expect(monthlyTab.getAttribute('aria-selected')).toBe('true');
    });
  });

  describe('Features Display', () => {
    it('should display plan features', () => {
      render(<PricingTable {...defaultProps} plans={samplePlans} />);

      // Check features exist (use getAllByText since they may appear multiple times)
      expect(screen.getAllByText('5 users').length).toBeGreaterThan(0);
      expect(screen.getAllByText('Basic support').length).toBeGreaterThan(0);
      expect(screen.getAllByText('Unlimited users').length).toBeGreaterThan(0);
    });

    it('should limit features shown based on maxFeaturesShown', () => {
      render(<PricingTable {...defaultProps} plans={samplePlans} maxFeaturesShown={3} />);

      // Pro plan has 7 features, should show "+4 more features"
      expect(screen.getByText(/\+4 more features/)).toBeTruthy();
    });

    it('should hide features when showFeatures is false', () => {
      render(<PricingTable {...defaultProps} plans={samplePlans} showFeatures={false} />);

      expect(screen.queryByText("What's included")).toBeNull();
      // Features should not be in the features section (but may still be in limits)
      expect(screen.queryByText('Basic support')).toBeNull();
    });
  });

  describe('Highlight Badge', () => {
    it('should display highlight badge for recommended plan', () => {
      render(<PricingTable {...defaultProps} plans={samplePlans} />);

      expect(screen.getByText('Most Popular')).toBeTruthy();
    });

    it('should not display highlight badge when highlightRecommended is false', () => {
      render(<PricingTable {...defaultProps} plans={samplePlans} highlightRecommended={false} />);

      expect(screen.queryByText('Most Popular')).toBeNull();
    });
  });

  describe('Trial Badge', () => {
    it('should display trial badge for plans with trial days', () => {
      render(<PricingTable {...defaultProps} plans={samplePlans} />);

      expect(screen.getByText('14-day free trial')).toBeTruthy();
    });

    it('should not display trial badge for current plan', () => {
      render(<PricingTable {...defaultProps} plans={samplePlans} currentPlanId="plan_pro" />);

      expect(screen.queryByText('14-day free trial')).toBeNull();
    });
  });

  describe('Current Plan', () => {
    it('should show current plan button text for current plan', () => {
      render(<PricingTable {...defaultProps} plans={samplePlans} currentPlanId="plan_pro" />);

      expect(screen.getByText('Current Plan')).toBeTruthy();
    });

    it('should disable button for current plan', () => {
      render(<PricingTable {...defaultProps} plans={samplePlans} currentPlanId="plan_pro" />);

      const currentPlanButton = screen.getByText('Current Plan');
      expect((currentPlanButton as HTMLButtonElement).disabled).toBe(true);
    });

    it('should show upgrade text for higher priced plans', () => {
      render(<PricingTable {...defaultProps} plans={samplePlans} currentPlanId="plan_free" />);

      // Pro and Enterprise should show "Upgrade"
      const upgradeButtons = screen.getAllByText('Upgrade');
      expect(upgradeButtons.length).toBe(2);
    });

    it('should show downgrade text for lower priced plans', () => {
      render(<PricingTable {...defaultProps} plans={samplePlans} currentPlanId="plan_enterprise" />);

      // Free and Pro should show "Downgrade"
      const downgradeButtons = screen.getAllByText('Downgrade');
      expect(downgradeButtons.length).toBe(2);
    });

    it('should use custom button texts', () => {
      render(
        <PricingTable
          {...defaultProps}
          plans={samplePlans}
          currentPlanId="plan_free"
          subscribeButtonText="Start Now"
          currentPlanButtonText="Your Plan"
          upgradeButtonText="Go Pro"
        />
      );

      expect(screen.getByText('Your Plan')).toBeTruthy();
      expect(screen.getAllByText('Go Pro').length).toBe(2);
    });
  });

  describe('Subscribe Action', () => {
    it('should call onSubscribe when subscribe button clicked', async () => {
      const onSubscribe = vi.fn().mockResolvedValue(undefined);

      render(
        <PricingTable
          {...defaultProps}
          plans={samplePlans}
          onSubscribe={onSubscribe}
        />
      );

      const subscribeButtons = screen.getAllByText('Get Started');
      fireEvent.click(subscribeButtons[0]); // Click Free plan

      await waitFor(() => {
        expect(onSubscribe).toHaveBeenCalledWith('plan_free', 'monthly');
      });
    });

    it('should call onSubscribe with yearly interval when yearly selected', async () => {
      const onSubscribe = vi.fn().mockResolvedValue(undefined);

      render(
        <PricingTable
          {...defaultProps}
          plans={samplePlans}
          onSubscribe={onSubscribe}
        />
      );

      // Switch to yearly
      const yearlyTab = screen.getByRole('tab', { name: /yearly/i });
      fireEvent.click(yearlyTab);

      // Click subscribe
      const subscribeButtons = screen.getAllByText('Get Started');
      fireEvent.click(subscribeButtons[0]);

      await waitFor(() => {
        expect(onSubscribe).toHaveBeenCalledWith('plan_free', 'yearly');
      });
    });

    it('should show loading state during subscription', async () => {
      let resolvePromise: () => void;
      const onSubscribe = vi.fn().mockReturnValue(
        new Promise<void>((resolve) => {
          resolvePromise = resolve;
        })
      );

      render(
        <PricingTable
          {...defaultProps}
          plans={samplePlans}
          onSubscribe={onSubscribe}
        />
      );

      const subscribeButtons = screen.getAllByText('Get Started');
      fireEvent.click(subscribeButtons[0]);

      await waitFor(() => {
        expect(screen.getByText(/processing/i)).toBeTruthy();
      });

      // Resolve the promise
      resolvePromise!();

      await waitFor(() => {
        expect(screen.queryByText(/processing/i)).toBeNull();
      });
    });

    it('should call onSubscribeSuccess after successful subscription', async () => {
      const onSubscribeSuccess = vi.fn();

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          data: {
            subscription_id: 'sub_123',
            plan_id: 'plan_pro',
            status: 'active'
          }
        })
      });

      render(
        <PricingTable
          {...defaultProps}
          plans={samplePlans}
          accessToken="test-token"
          tenantId="test-tenant"
          onSubscribeSuccess={onSubscribeSuccess}
        />
      );

      // Find and click the Pro plan button (highlighted one)
      const proCard = screen.getByText('Pro').closest('[role="listitem"]');
      const subscribeButton = within(proCard!).getByRole('button');
      fireEvent.click(subscribeButton);

      await waitFor(() => {
        expect(onSubscribeSuccess).toHaveBeenCalledWith({
          subscription_id: 'sub_123',
          plan_id: 'plan_pro',
          status: 'active'
        });
      });
    });

    it('should not allow clicking current plan button', () => {
      const onSubscribe = vi.fn();

      render(
        <PricingTable
          {...defaultProps}
          plans={samplePlans}
          currentPlanId="plan_pro"
          onSubscribe={onSubscribe}
        />
      );

      const currentPlanButton = screen.getByText('Current Plan');
      fireEvent.click(currentPlanButton);

      expect(onSubscribe).not.toHaveBeenCalled();
    });
  });

  describe('Error Handling', () => {
    it('should display API error', async () => {
      const onError = vi.fn();

      mockFetch.mockResolvedValueOnce({
        ok: false,
        json: () => Promise.resolve({
          error: { message: 'Failed to load plans' }
        })
      });

      render(<PricingTable {...defaultProps} onError={onError} />);

      await waitFor(() => {
        // When API fails, onError should be called
        expect(onError).toHaveBeenCalled();
      });
    });

    it('should display subscription error', async () => {
      const onSubscribe = vi.fn().mockRejectedValue(new Error('Payment failed'));
      const onError = vi.fn();

      render(
        <PricingTable
          {...defaultProps}
          plans={samplePlans}
          onSubscribe={onSubscribe}
          onError={onError}
        />
      );

      const subscribeButtons = screen.getAllByText('Get Started');
      fireEvent.click(subscribeButtons[0]);

      await waitFor(() => {
        expect(screen.getByText('Payment failed')).toBeTruthy();
        expect(onError).toHaveBeenCalled();
      });
    });

    it('should call onError callback on API error', async () => {
      const onError = vi.fn();

      mockFetch.mockResolvedValueOnce({
        ok: false,
        json: () => Promise.resolve({
          error: { message: 'Server error' }
        })
      });

      render(<PricingTable {...defaultProps} onError={onError} />);

      await waitFor(() => {
        expect(onError).toHaveBeenCalledWith(expect.any(Error));
      });
    });
  });

  describe('Contact Sales', () => {
    it('should show contact sales section when enabled', () => {
      const onContactSales = vi.fn();

      render(
        <PricingTable
          {...defaultProps}
          plans={samplePlans}
          showContactSales
          onContactSales={onContactSales}
        />
      );

      expect(screen.getByText(/need a custom plan/i)).toBeTruthy();
      expect(screen.getByText('Contact Sales')).toBeTruthy();
    });

    it('should call onContactSales when button clicked', () => {
      const onContactSales = vi.fn();

      render(
        <PricingTable
          {...defaultProps}
          plans={samplePlans}
          showContactSales
          onContactSales={onContactSales}
        />
      );

      fireEvent.click(screen.getByText('Contact Sales'));

      expect(onContactSales).toHaveBeenCalled();
    });

    it('should hide contact sales when showContactSales is false', () => {
      render(
        <PricingTable
          {...defaultProps}
          plans={samplePlans}
          showContactSales={false}
        />
      );

      expect(screen.queryByText('Contact Sales')).toBeNull();
    });
  });

  describe('Limits Display', () => {
    it('should display plan limits', () => {
      render(<PricingTable {...defaultProps} plans={samplePlans} />);

      // Free plan has 5 users limit - check it exists (may appear multiple times)
      expect(screen.getAllByText('5 users').length).toBeGreaterThan(0);
      
      // Free plan has 1 GB storage
      expect(screen.getAllByText('1 GB').length).toBeGreaterThan(0);
    });

    it('should show Unlimited for unlimited limits', () => {
      render(<PricingTable {...defaultProps} plans={samplePlans} />);

      // Pro and Enterprise have unlimited users
      const unlimitedElements = screen.getAllByText('Unlimited');
      expect(unlimitedElements.length).toBeGreaterThan(0);
    });

    it('should hide limits in compact mode', () => {
      render(<PricingTable {...defaultProps} plans={samplePlans} compact />);

      // Limits section should not be visible (check for limit label)
      expect(screen.queryByText('Storage Gb')).toBeNull();
    });
  });

  describe('Accessibility', () => {
    it('should have proper ARIA roles', () => {
      render(<PricingTable {...defaultProps} plans={samplePlans} />);

      // Plans grid has role="list" - use getAllByRole since feature lists also have list role
      const lists = screen.getAllByRole('list');
      expect(lists.length).toBeGreaterThan(0);
      
      // Each plan card has data-plan-id attribute
      const planCards = document.querySelectorAll('[data-plan-id]');
      expect(planCards.length).toBe(3);
      
      expect(screen.getByRole('tablist')).toBeTruthy();
    });

    it('should have proper button aria-labels', () => {
      render(<PricingTable {...defaultProps} plans={samplePlans} />);

      expect(screen.getByRole('button', { name: /get started - free/i })).toBeTruthy();
      expect(screen.getByRole('button', { name: /get started - pro/i })).toBeTruthy();
    });

    it('should have error role for error messages', async () => {
      // Provide plans so we don't show empty state, then trigger subscription error
      const onSubscribe = vi.fn().mockRejectedValue(new Error('Subscription failed'));

      render(
        <PricingTable
          {...defaultProps}
          plans={samplePlans}
          onSubscribe={onSubscribe}
        />
      );

      // Click subscribe to trigger error
      const subscribeButtons = screen.getAllByText('Get Started');
      fireEvent.click(subscribeButtons[0]);

      await waitFor(() => {
        expect(screen.getByRole('alert')).toBeTruthy();
      });
    });
  });

  describe('API Integration', () => {
    it('should fetch plans with correct URL', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ data: { plans: samplePlans } })
      });

      render(<PricingTable {...defaultProps} />);

      await waitFor(() => {
        expect(mockFetch).toHaveBeenCalledWith(
          'https://api.zalt.io/billing/plans?realm_id=test-realm-123',
          expect.objectContaining({
            method: 'GET',
            headers: expect.objectContaining({
              'Content-Type': 'application/json'
            })
          })
        );
      });
    });

    it('should include authorization header when accessToken provided', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ data: { plans: samplePlans } })
      });

      render(<PricingTable {...defaultProps} accessToken="test-token" />);

      await waitFor(() => {
        expect(mockFetch).toHaveBeenCalledWith(
          expect.any(String),
          expect.objectContaining({
            headers: expect.objectContaining({
              'Authorization': 'Bearer test-token'
            })
          })
        );
      });
    });

    it('should filter inactive plans', async () => {
      const plansWithInactive = [
        ...samplePlans,
        {
          ...samplePlans[0],
          id: 'plan_inactive',
          name: 'Inactive Plan',
          status: 'inactive' as const
        }
      ];

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ data: { plans: plansWithInactive } })
      });

      render(<PricingTable {...defaultProps} />);

      await waitFor(() => {
        // Check that Free plan exists (by heading)
        expect(screen.getByRole('heading', { name: 'Free' })).toBeTruthy();
        // Check that Inactive Plan does not exist
        expect(screen.queryByRole('heading', { name: 'Inactive Plan' })).toBeNull();
      });
    });

    it('should sort plans by sort_order', async () => {
      const unsortedPlans = [
        { ...samplePlans[2], sort_order: 1 }, // Enterprise first
        { ...samplePlans[0], sort_order: 3 }, // Free last
        { ...samplePlans[1], sort_order: 2 }, // Pro middle
      ];

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ data: { plans: unsortedPlans } })
      });

      render(<PricingTable {...defaultProps} />);

      await waitFor(() => {
        const planCards = document.querySelectorAll('[data-plan-id]');
        expect(planCards[0].getAttribute('data-plan-id')).toBe('plan_enterprise');
        expect(planCards[1].getAttribute('data-plan-id')).toBe('plan_pro');
        expect(planCards[2].getAttribute('data-plan-id')).toBe('plan_free');
      });
    });
  });

  describe('Compact Mode', () => {
    it('should hide descriptions in compact mode', () => {
      render(<PricingTable {...defaultProps} plans={samplePlans} compact />);

      expect(screen.queryByText('Perfect for getting started')).toBeNull();
      expect(screen.queryByText('For growing teams')).toBeNull();
    });

    it('should hide limits in compact mode', () => {
      render(<PricingTable {...defaultProps} plans={samplePlans} compact />);

      // Limits section should not be visible
      expect(screen.queryByText('Storage Gb')).toBeNull();
    });
  });
});
