/**
 * BillingPortal Component Tests
 * 
 * Validates: Requirement 7.8 (SDK BillingPortal component)
 * 
 * Tests:
 * - Render subscription info
 * - Payment method display (masked for security)
 * - Invoice history
 * - Cancel subscription
 * - Loading and error states
 * - Accessibility
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react';
import { BillingPortal, type Subscription, type BillingPlan, type PaymentMethod, type Invoice } from '../BillingPortal';

// Mock fetch globally
const mockFetch = vi.fn();
global.fetch = mockFetch;

// Sample data for testing
const sampleSubscription: Subscription = {
  id: 'sub_test123',
  tenant_id: 'tenant_test',
  plan_id: 'plan_pro',
  stripe_subscription_id: 'sub_stripe123',
  status: 'active',
  current_period_start: '2024-01-01T00:00:00Z',
  current_period_end: '2024-02-01T00:00:00Z',
  created_at: '2024-01-01T00:00:00Z',
};

const samplePlan: BillingPlan = {
  id: 'plan_pro',
  realm_id: 'test-realm',
  name: 'Pro Plan',
  description: 'For growing teams',
  type: 'per_user',
  price_monthly: 2900,
  price_yearly: 29000,
  currency: 'usd',
  features: ['Unlimited users', 'Priority support'],
  limits: { users: -1 },
  status: 'active',
  created_at: '2024-01-01T00:00:00Z',
};


const samplePaymentMethods: PaymentMethod[] = [
  {
    id: 'pm_test123',
    type: 'card',
    brand: 'visa',
    last4: '4242',
    exp_month: 12,
    exp_year: 2025,
    is_default: true,
  },
];

const sampleInvoices: Invoice[] = [
  {
    id: 'inv_test1',
    number: 'INV-001',
    status: 'paid',
    amount_due: 2900,
    amount_paid: 2900,
    currency: 'usd',
    period_start: '2024-01-01T00:00:00Z',
    period_end: '2024-02-01T00:00:00Z',
    invoice_pdf: 'https://stripe.com/invoice.pdf',
    created_at: '2024-01-01T00:00:00Z',
  },
  {
    id: 'inv_test2',
    number: 'INV-002',
    status: 'open',
    amount_due: 2900,
    amount_paid: 0,
    currency: 'usd',
    period_start: '2024-02-01T00:00:00Z',
    period_end: '2024-03-01T00:00:00Z',
    hosted_invoice_url: 'https://stripe.com/invoice',
    created_at: '2024-02-01T00:00:00Z',
  },
];

describe('BillingPortal Component', () => {
  const defaultProps = {
    apiUrl: 'https://api.zalt.io',
    accessToken: 'test-token',
    tenantId: 'tenant_test',
    realmId: 'test-realm',
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

      render(<BillingPortal {...defaultProps} />);

      expect(document.querySelector('.zalt-billing-portal')).toBeTruthy();
    });

    it('should render subscription info from props', () => {
      render(
        <BillingPortal
          {...defaultProps}
          subscription={sampleSubscription}
          plan={samplePlan}
        />
      );

      expect(screen.getByText('Pro Plan')).toBeTruthy();
      expect(screen.getByText('Active')).toBeTruthy();
    });

    it('should render no subscription state', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
        json: () => Promise.resolve({ error: { message: 'Not found' } }),
      });

      render(<BillingPortal {...defaultProps} />);

      await waitFor(() => {
        expect(screen.getByText('No Active Subscription')).toBeTruthy();
      });
    });

    it('should apply custom className', () => {
      const { container } = render(
        <BillingPortal
          {...defaultProps}
          subscription={sampleSubscription}
          plan={samplePlan}
          className="custom-billing"
        />
      );

      expect(container.querySelector('.custom-billing')).toBeTruthy();
    });
  });


  describe('Subscription Display', () => {
    it('should display plan name and price', () => {
      render(
        <BillingPortal
          {...defaultProps}
          subscription={sampleSubscription}
          plan={samplePlan}
        />
      );

      expect(screen.getByText('Pro Plan')).toBeTruthy();
      expect(screen.getByText('$29/month')).toBeTruthy();
    });

    it('should display active status with correct styling', () => {
      render(
        <BillingPortal
          {...defaultProps}
          subscription={sampleSubscription}
          plan={samplePlan}
        />
      );

      expect(screen.getByText('Active')).toBeTruthy();
    });

    it('should display trialing status', () => {
      const trialingSubscription: Subscription = {
        ...sampleSubscription,
        status: 'trialing',
        trial_start: '2024-01-01T00:00:00Z',
        trial_end: '2024-01-15T00:00:00Z',
      };

      render(
        <BillingPortal
          {...defaultProps}
          subscription={trialingSubscription}
          plan={samplePlan}
        />
      );

      expect(screen.getByText('Trial')).toBeTruthy();
    });

    it('should display past_due status with warning', () => {
      const pastDueSubscription: Subscription = {
        ...sampleSubscription,
        status: 'past_due',
      };

      render(
        <BillingPortal
          {...defaultProps}
          subscription={pastDueSubscription}
          plan={samplePlan}
        />
      );

      expect(screen.getByText('Past Due')).toBeTruthy();
      expect(screen.getByText(/payment is past due/i)).toBeTruthy();
    });

    it('should display canceled status', () => {
      const canceledSubscription: Subscription = {
        ...sampleSubscription,
        status: 'canceled',
        canceled_at: '2024-01-15T00:00:00Z',
      };

      render(
        <BillingPortal
          {...defaultProps}
          subscription={canceledSubscription}
          plan={samplePlan}
        />
      );

      expect(screen.getByText('Canceled')).toBeTruthy();
    });

    it('should display billing period dates', () => {
      render(
        <BillingPortal
          {...defaultProps}
          subscription={sampleSubscription}
          plan={samplePlan}
        />
      );

      expect(screen.getByText(/Current Billing Period/i)).toBeTruthy();
      expect(screen.getByText(/Jan 1, 2024/)).toBeTruthy();
    });

    it('should display cancel warning when cancel_at_period_end is true', () => {
      const cancelingSubscription: Subscription = {
        ...sampleSubscription,
        cancel_at_period_end: true,
      };

      render(
        <BillingPortal
          {...defaultProps}
          subscription={cancelingSubscription}
          plan={samplePlan}
        />
      );

      expect(screen.getByText(/will be canceled/i)).toBeTruthy();
    });
  });


  describe('Payment Methods', () => {
    it('should display payment methods when provided', async () => {
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: sampleSubscription }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: samplePlan }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: { payment_methods: samplePaymentMethods } }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: { invoices: [] } }),
        });

      render(<BillingPortal {...defaultProps} />);

      await waitFor(() => {
        expect(screen.getByText('Payment Methods')).toBeTruthy();
      });
    });

    it('should mask card number showing only last 4 digits', async () => {
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: sampleSubscription }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: samplePlan }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: { payment_methods: samplePaymentMethods } }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: { invoices: [] } }),
        });

      render(<BillingPortal {...defaultProps} />);

      await waitFor(() => {
        // Should show masked card number with last 4 digits
        expect(screen.getByText(/•••• •••• •••• 4242/)).toBeTruthy();
      });
    });

    it('should display card expiry date', async () => {
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: sampleSubscription }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: samplePlan }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: { payment_methods: samplePaymentMethods } }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: { invoices: [] } }),
        });

      render(<BillingPortal {...defaultProps} />);

      await waitFor(() => {
        expect(screen.getByText(/Expires 12\/2025/)).toBeTruthy();
      });
    });

    it('should show default badge for default payment method', async () => {
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: sampleSubscription }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: samplePlan }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: { payment_methods: samplePaymentMethods } }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: { invoices: [] } }),
        });

      render(<BillingPortal {...defaultProps} />);

      await waitFor(() => {
        expect(screen.getByText('Default')).toBeTruthy();
      });
    });

    it('should hide payment methods when showPaymentMethods is false', () => {
      render(
        <BillingPortal
          {...defaultProps}
          subscription={sampleSubscription}
          plan={samplePlan}
          showPaymentMethods={false}
        />
      );

      expect(screen.queryByText('Payment Methods')).toBeNull();
    });

    it('should call onUpdatePaymentMethod when update button clicked', async () => {
      const onUpdatePaymentMethod = vi.fn();

      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: sampleSubscription }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: samplePlan }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: { payment_methods: samplePaymentMethods } }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: { invoices: [] } }),
        });

      render(
        <BillingPortal
          {...defaultProps}
          onUpdatePaymentMethod={onUpdatePaymentMethod}
        />
      );

      await waitFor(() => {
        const updateButton = screen.getByText('Update');
        fireEvent.click(updateButton);
        expect(onUpdatePaymentMethod).toHaveBeenCalled();
      });
    });
  });


  describe('Invoice History', () => {
    it('should display invoices when provided', async () => {
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: sampleSubscription }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: samplePlan }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: { payment_methods: [] } }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: { invoices: sampleInvoices } }),
        });

      render(<BillingPortal {...defaultProps} />);

      await waitFor(() => {
        expect(screen.getByText('Invoice History')).toBeTruthy();
      });
    });

    it('should display invoice amounts', async () => {
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: sampleSubscription }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: samplePlan }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: { payment_methods: [] } }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: { invoices: sampleInvoices } }),
        });

      render(<BillingPortal {...defaultProps} />);

      await waitFor(() => {
        // Should show $29 for each invoice
        const amounts = screen.getAllByText('$29');
        expect(amounts.length).toBeGreaterThan(0);
      });
    });

    it('should display invoice status badges', async () => {
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: sampleSubscription }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: samplePlan }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: { payment_methods: [] } }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: { invoices: sampleInvoices } }),
        });

      render(<BillingPortal {...defaultProps} />);

      await waitFor(() => {
        expect(screen.getByText('Paid')).toBeTruthy();
        expect(screen.getByText('Open')).toBeTruthy();
      });
    });

    it('should show download link for PDF invoices', async () => {
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: sampleSubscription }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: samplePlan }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: { payment_methods: [] } }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: { invoices: sampleInvoices } }),
        });

      render(<BillingPortal {...defaultProps} />);

      await waitFor(() => {
        expect(screen.getByText('Download')).toBeTruthy();
      });
    });

    it('should show view link for hosted invoices', async () => {
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: sampleSubscription }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: samplePlan }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: { payment_methods: [] } }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: { invoices: sampleInvoices } }),
        });

      render(<BillingPortal {...defaultProps} />);

      await waitFor(() => {
        expect(screen.getByText('View')).toBeTruthy();
      });
    });

    it('should hide invoices when showInvoices is false', () => {
      render(
        <BillingPortal
          {...defaultProps}
          subscription={sampleSubscription}
          plan={samplePlan}
          showInvoices={false}
        />
      );

      expect(screen.queryByText('Invoice History')).toBeNull();
    });
  });


  describe('Cancel Subscription', () => {
    it('should show cancel button for active subscription', () => {
      render(
        <BillingPortal
          {...defaultProps}
          subscription={sampleSubscription}
          plan={samplePlan}
        />
      );

      expect(screen.getByText('Cancel Subscription')).toBeTruthy();
    });

    it('should open cancel modal when cancel button clicked', () => {
      render(
        <BillingPortal
          {...defaultProps}
          subscription={sampleSubscription}
          plan={samplePlan}
        />
      );

      fireEvent.click(screen.getByText('Cancel Subscription'));

      expect(screen.getByRole('dialog')).toBeTruthy();
      expect(screen.getByText(/Are you sure you want to cancel/i)).toBeTruthy();
    });

    it('should close modal when Keep Subscription clicked', () => {
      render(
        <BillingPortal
          {...defaultProps}
          subscription={sampleSubscription}
          plan={samplePlan}
        />
      );

      fireEvent.click(screen.getByText('Cancel Subscription'));
      fireEvent.click(screen.getByText('Keep Subscription'));

      expect(screen.queryByRole('dialog')).toBeNull();
    });

    it('should call onCancelSubscription when confirmed', async () => {
      const onCancelSubscription = vi.fn().mockResolvedValue(undefined);

      render(
        <BillingPortal
          {...defaultProps}
          subscription={sampleSubscription}
          plan={samplePlan}
          onCancelSubscription={onCancelSubscription}
        />
      );

      fireEvent.click(screen.getByText('Cancel Subscription'));
      
      // Click the confirm button in the modal (use getAllByText and get the button)
      const modal = screen.getByRole('dialog');
      const buttons = within(modal).getAllByRole('button');
      const confirmButton = buttons.find(btn => btn.textContent === 'Cancel Subscription');
      fireEvent.click(confirmButton!);

      await waitFor(() => {
        expect(onCancelSubscription).toHaveBeenCalledWith('sub_test123', true);
      });
    });

    it('should call onCancelSuccess after successful cancellation', async () => {
      const onCancelSuccess = vi.fn();
      const onCancelSubscription = vi.fn().mockResolvedValue(undefined);

      render(
        <BillingPortal
          {...defaultProps}
          subscription={sampleSubscription}
          plan={samplePlan}
          onCancelSubscription={onCancelSubscription}
          onCancelSuccess={onCancelSuccess}
        />
      );

      fireEvent.click(screen.getByText('Cancel Subscription'));
      
      const modal = screen.getByRole('dialog');
      const buttons = within(modal).getAllByRole('button');
      const confirmButton = buttons.find(btn => btn.textContent === 'Cancel Subscription');
      fireEvent.click(confirmButton!);

      await waitFor(() => {
        expect(onCancelSuccess).toHaveBeenCalled();
      });
    });

    it('should show reactivate button when subscription is set to cancel', () => {
      const cancelingSubscription: Subscription = {
        ...sampleSubscription,
        cancel_at_period_end: true,
      };

      render(
        <BillingPortal
          {...defaultProps}
          subscription={cancelingSubscription}
          plan={samplePlan}
        />
      );

      expect(screen.getByText('Reactivate')).toBeTruthy();
      expect(screen.queryByText('Cancel Subscription')).toBeNull();
    });

    it('should not show cancel button for canceled subscription', () => {
      const canceledSubscription: Subscription = {
        ...sampleSubscription,
        status: 'canceled',
      };

      render(
        <BillingPortal
          {...defaultProps}
          subscription={canceledSubscription}
          plan={samplePlan}
        />
      );

      expect(screen.queryByText('Cancel Subscription')).toBeNull();
    });

    it('should use custom cancel button text', () => {
      render(
        <BillingPortal
          {...defaultProps}
          subscription={sampleSubscription}
          plan={samplePlan}
          cancelButtonText="End Subscription"
        />
      );

      expect(screen.getByText('End Subscription')).toBeTruthy();
    });

    it('should use custom reactivate button text', () => {
      const cancelingSubscription: Subscription = {
        ...sampleSubscription,
        cancel_at_period_end: true,
      };

      render(
        <BillingPortal
          {...defaultProps}
          subscription={cancelingSubscription}
          plan={samplePlan}
          reactivateButtonText="Resume Subscription"
        />
      );

      expect(screen.getByText('Resume Subscription')).toBeTruthy();
    });
  });


  describe('Change Plan', () => {
    it('should show change plan button when enabled', () => {
      const onChangePlan = vi.fn();

      render(
        <BillingPortal
          {...defaultProps}
          subscription={sampleSubscription}
          plan={samplePlan}
          showChangePlan
          onChangePlan={onChangePlan}
        />
      );

      expect(screen.getByText('Change Plan')).toBeTruthy();
    });

    it('should call onChangePlan when button clicked', () => {
      const onChangePlan = vi.fn();

      render(
        <BillingPortal
          {...defaultProps}
          subscription={sampleSubscription}
          plan={samplePlan}
          showChangePlan
          onChangePlan={onChangePlan}
        />
      );

      fireEvent.click(screen.getByText('Change Plan'));

      expect(onChangePlan).toHaveBeenCalled();
    });

    it('should hide change plan button when showChangePlan is false', () => {
      render(
        <BillingPortal
          {...defaultProps}
          subscription={sampleSubscription}
          plan={samplePlan}
          showChangePlan={false}
        />
      );

      expect(screen.queryByText('Change Plan')).toBeNull();
    });

    it('should show View Plans button when no subscription', async () => {
      const onChangePlan = vi.fn();

      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
        json: () => Promise.resolve({ error: { message: 'Not found' } }),
      });

      render(
        <BillingPortal
          {...defaultProps}
          showChangePlan
          onChangePlan={onChangePlan}
        />
      );

      await waitFor(() => {
        expect(screen.getByText('View Plans')).toBeTruthy();
      });
    });

    it('should show Subscribe Again for canceled subscription', () => {
      const onChangePlan = vi.fn();
      const canceledSubscription: Subscription = {
        ...sampleSubscription,
        status: 'canceled',
      };

      render(
        <BillingPortal
          {...defaultProps}
          subscription={canceledSubscription}
          plan={samplePlan}
          showChangePlan
          onChangePlan={onChangePlan}
        />
      );

      expect(screen.getByText('Subscribe Again')).toBeTruthy();
    });
  });

  describe('Error Handling', () => {
    it('should display API error', async () => {
      const onError = vi.fn();

      mockFetch.mockResolvedValueOnce({
        ok: false,
        json: () => Promise.resolve({
          error: { message: 'Failed to load subscription' },
        }),
      });

      render(<BillingPortal {...defaultProps} onError={onError} />);

      await waitFor(() => {
        expect(onError).toHaveBeenCalled();
      });
    });

    it('should display cancel error', async () => {
      const onCancelSubscription = vi.fn().mockRejectedValue(new Error('Cancel failed'));
      const onError = vi.fn();

      render(
        <BillingPortal
          {...defaultProps}
          subscription={sampleSubscription}
          plan={samplePlan}
          onCancelSubscription={onCancelSubscription}
          onError={onError}
        />
      );

      fireEvent.click(screen.getByText('Cancel Subscription'));
      
      const modal = screen.getByRole('dialog');
      const buttons = within(modal).getAllByRole('button');
      const confirmButton = buttons.find(btn => btn.textContent === 'Cancel Subscription');
      fireEvent.click(confirmButton!);

      await waitFor(() => {
        expect(screen.getByText('Cancel failed')).toBeTruthy();
        expect(onError).toHaveBeenCalled();
      });
    });
  });


  describe('Accessibility', () => {
    it('should have proper section headings', () => {
      render(
        <BillingPortal
          {...defaultProps}
          subscription={sampleSubscription}
          plan={samplePlan}
        />
      );

      expect(screen.getByRole('heading', { name: /Current Subscription/i })).toBeTruthy();
    });

    it('should have proper ARIA labels on sections', () => {
      render(
        <BillingPortal
          {...defaultProps}
          subscription={sampleSubscription}
          plan={samplePlan}
        />
      );

      expect(document.querySelector('[aria-labelledby="subscription-title"]')).toBeTruthy();
    });

    it('should have proper dialog role for cancel modal', () => {
      render(
        <BillingPortal
          {...defaultProps}
          subscription={sampleSubscription}
          plan={samplePlan}
        />
      );

      fireEvent.click(screen.getByText('Cancel Subscription'));

      const modal = screen.getByRole('dialog');
      expect(modal.getAttribute('aria-modal')).toBe('true');
    });

    it('should have error role for error messages', async () => {
      const onCancelSubscription = vi.fn().mockRejectedValue(new Error('Error'));

      render(
        <BillingPortal
          {...defaultProps}
          subscription={sampleSubscription}
          plan={samplePlan}
          onCancelSubscription={onCancelSubscription}
        />
      );

      fireEvent.click(screen.getByText('Cancel Subscription'));
      
      const modal = screen.getByRole('dialog');
      const buttons = within(modal).getAllByRole('button');
      const confirmButton = buttons.find(btn => btn.textContent === 'Cancel Subscription');
      fireEvent.click(confirmButton!);

      await waitFor(() => {
        expect(screen.getByRole('alert')).toBeTruthy();
      });
    });
  });

  describe('API Integration', () => {
    it('should fetch subscription with correct URL', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ data: sampleSubscription }),
      });

      render(<BillingPortal {...defaultProps} />);

      await waitFor(() => {
        expect(mockFetch).toHaveBeenCalledWith(
          'https://api.zalt.io/billing/subscription?tenant_id=tenant_test',
          expect.objectContaining({
            method: 'GET',
            headers: expect.objectContaining({
              'Authorization': 'Bearer test-token',
              'Content-Type': 'application/json',
            }),
          })
        );
      });
    });

    it('should call cancel API when no custom handler provided', async () => {
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: sampleSubscription }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({}),
        });

      render(<BillingPortal {...defaultProps} />);

      await waitFor(() => {
        expect(screen.getByText('Cancel Subscription')).toBeTruthy();
      });

      fireEvent.click(screen.getByText('Cancel Subscription'));
      
      const modal = screen.getByRole('dialog');
      const buttons = within(modal).getAllByRole('button');
      const confirmButton = buttons.find(btn => btn.textContent === 'Cancel Subscription');
      
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({}),
      });
      
      fireEvent.click(confirmButton!);

      await waitFor(() => {
        expect(mockFetch).toHaveBeenCalledWith(
          'https://api.zalt.io/billing/cancel',
          expect.objectContaining({
            method: 'POST',
            body: expect.stringContaining('sub_test123'),
          })
        );
      });
    });
  });

  describe('Compact Mode', () => {
    it('should hide billing period in compact mode', () => {
      render(
        <BillingPortal
          {...defaultProps}
          subscription={sampleSubscription}
          plan={samplePlan}
          compact
        />
      );

      expect(screen.queryByText(/Current Billing Period/i)).toBeNull();
    });
  });

  describe('Security - Payment Info Masking', () => {
    it('should never display full card number', async () => {
      const fullCardNumber = '4242424242424242';
      
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: sampleSubscription }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: samplePlan }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: { payment_methods: samplePaymentMethods } }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: { invoices: [] } }),
        });

      render(<BillingPortal {...defaultProps} />);

      await waitFor(() => {
        // Full card number should never appear
        expect(screen.queryByText(fullCardNumber)).toBeNull();
        // Only last 4 digits should be visible
        expect(screen.getByText(/•••• •••• •••• 4242/)).toBeTruthy();
      });
    });

    it('should only show last 4 digits of card', async () => {
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: sampleSubscription }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: samplePlan }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: { payment_methods: samplePaymentMethods } }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve({ data: { invoices: [] } }),
        });

      const { container } = render(<BillingPortal {...defaultProps} />);

      await waitFor(() => {
        // Verify the masked format is used
        const cardText = container.textContent;
        expect(cardText).toContain('4242');
        expect(cardText).toContain('••••');
      });
    });
  });
});
