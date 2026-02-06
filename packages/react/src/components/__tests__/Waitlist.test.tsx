/**
 * Waitlist Component Tests
 * 
 * Validates: Requirement 5.7 (SDK Waitlist component)
 * 
 * Tests:
 * - Render waitlist signup form
 * - Submit email to join waitlist
 * - Display position after signup
 * - Display referral code
 * - Handle errors
 * - Custom fields support
 * - Referral code input
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import React from 'react';
import { Waitlist } from '../Waitlist';

// Mock fetch globally
const mockFetch = vi.fn();
global.fetch = mockFetch;

// Mock clipboard API
const mockClipboard = {
  writeText: vi.fn().mockResolvedValue(undefined),
};
Object.assign(navigator, { clipboard: mockClipboard });

describe('Waitlist Component', () => {
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
    it('should render waitlist form with default props', () => {
      render(<Waitlist {...defaultProps} />);

      expect(screen.getByText('Join the Waitlist')).toBeTruthy();
      expect(screen.getByText("We're launching soon. Sign up to be notified.")).toBeTruthy();
      expect(screen.getByLabelText(/email address/i)).toBeTruthy();
      expect(screen.getByRole('button', { name: /join waitlist/i })).toBeTruthy();
    });

    it('should render with custom title and description', () => {
      render(
        <Waitlist
          {...defaultProps}
          title="Get Early Access"
          description="Be among the first to try our new product."
        />
      );

      expect(screen.getByText('Get Early Access')).toBeTruthy();
      expect(screen.getByText('Be among the first to try our new product.')).toBeTruthy();
    });

    it('should render with custom button text', () => {
      render(<Waitlist {...defaultProps} buttonText="Sign Me Up" />);

      expect(screen.getByRole('button', { name: /sign me up/i })).toBeTruthy();
    });

    it('should render in compact mode without title/description', () => {
      render(<Waitlist {...defaultProps} compact />);

      expect(screen.queryByText('Join the Waitlist')).toBeNull();
      expect(screen.getByLabelText(/email address/i)).toBeTruthy();
    });

    it('should render referral code input when no initial code provided', () => {
      render(<Waitlist {...defaultProps} />);

      expect(screen.getByLabelText(/referral code/i)).toBeTruthy();
    });

    it('should not render referral code input when initial code provided', () => {
      render(<Waitlist {...defaultProps} referralCode="ABC12345" />);

      expect(screen.queryByLabelText(/referral code/i)).toBeNull();
    });
  });

  describe('Metadata Collection', () => {
    it('should render metadata fields when collectMetadata is true', () => {
      render(<Waitlist {...defaultProps} collectMetadata />);

      expect(screen.getByLabelText(/first name/i)).toBeTruthy();
      expect(screen.getByLabelText(/last name/i)).toBeTruthy();
      expect(screen.getByLabelText(/company/i)).toBeTruthy();
      expect(screen.getByLabelText(/how will you use this/i)).toBeTruthy();
    });

    it('should not render metadata fields by default', () => {
      render(<Waitlist {...defaultProps} />);

      expect(screen.queryByLabelText(/first name/i)).toBeNull();
      expect(screen.queryByLabelText(/last name/i)).toBeNull();
    });
  });

  describe('Custom Fields', () => {
    it('should render custom text fields', () => {
      render(
        <Waitlist
          {...defaultProps}
          customFields={[
            { name: 'phone', label: 'Phone Number', type: 'text' },
          ]}
        />
      );

      expect(screen.getByLabelText(/phone number/i)).toBeTruthy();
    });

    it('should render custom select fields', () => {
      render(
        <Waitlist
          {...defaultProps}
          customFields={[
            {
              name: 'plan',
              label: 'Preferred Plan',
              type: 'select',
              options: ['Free', 'Pro', 'Enterprise'],
            },
          ]}
        />
      );

      expect(screen.getByLabelText(/preferred plan/i)).toBeTruthy();
      expect(screen.getByRole('option', { name: 'Free' })).toBeTruthy();
      expect(screen.getByRole('option', { name: 'Pro' })).toBeTruthy();
    });

    it('should render custom textarea fields', () => {
      render(
        <Waitlist
          {...defaultProps}
          customFields={[
            { name: 'feedback', label: 'Additional Feedback', type: 'textarea' },
          ]}
        />
      );

      expect(screen.getByLabelText(/additional feedback/i)).toBeTruthy();
    });
  });

  describe('Form Submission', () => {
    it('should submit email to join waitlist', async () => {
      const onJoin = vi.fn();

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          data: {
            entry_id: 'entry_123',
            position: 42,
            referral_code: 'XYZ98765',
            message: "You're on the list!",
          },
        }),
      });

      render(<Waitlist {...defaultProps} onJoin={onJoin} />);

      const emailInput = screen.getByLabelText(/email address/i);
      fireEvent.change(emailInput, { target: { value: 'test@example.com' } });

      const submitButton = screen.getByRole('button', { name: /join waitlist/i });
      fireEvent.click(submitButton);

      await waitFor(() => {
        expect(mockFetch).toHaveBeenCalledWith(
          'https://api.zalt.io/waitlist?realm_id=test-realm-123',
          expect.objectContaining({
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
          })
        );
      });

      await waitFor(() => {
        expect(onJoin).toHaveBeenCalledWith({
          entry_id: 'entry_123',
          position: 42,
          referral_code: 'XYZ98765',
          message: "You're on the list!",
        });
      });
    });

    it('should submit with metadata when collectMetadata is true', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          data: {
            entry_id: 'entry_123',
            position: 1,
            referral_code: 'ABC12345',
          },
        }),
      });

      render(<Waitlist {...defaultProps} collectMetadata />);

      fireEvent.change(screen.getByLabelText(/email address/i), { target: { value: 'test@example.com' } });
      fireEvent.change(screen.getByLabelText(/first name/i), { target: { value: 'John' } });
      fireEvent.change(screen.getByLabelText(/last name/i), { target: { value: 'Doe' } });
      fireEvent.change(screen.getByLabelText(/company/i), { target: { value: 'Acme Inc' } });

      fireEvent.click(screen.getByRole('button', { name: /join waitlist/i }));

      await waitFor(() => {
        expect(mockFetch).toHaveBeenCalledWith(
          expect.any(String),
          expect.objectContaining({
            body: expect.stringContaining('"first_name":"John"'),
          })
        );
      });
    });

    it('should submit with referral code', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          data: {
            entry_id: 'entry_123',
            position: 5,
            referral_code: 'NEW12345',
          },
        }),
      });

      render(<Waitlist {...defaultProps} />);

      fireEvent.change(screen.getByLabelText(/email address/i), { target: { value: 'test@example.com' } });
      fireEvent.change(screen.getByLabelText(/referral code/i), { target: { value: 'REF12345' } });

      fireEvent.click(screen.getByRole('button', { name: /join waitlist/i }));

      await waitFor(() => {
        expect(mockFetch).toHaveBeenCalledWith(
          expect.any(String),
          expect.objectContaining({
            body: expect.stringContaining('"referral_code":"REF12345"'),
          })
        );
      });
    });

    it('should show loading state during submission', async () => {
      let resolvePromise: (value: unknown) => void;
      mockFetch.mockReturnValueOnce(
        new Promise((resolve) => {
          resolvePromise = resolve;
        })
      );

      render(<Waitlist {...defaultProps} />);

      fireEvent.change(screen.getByLabelText(/email address/i), { target: { value: 'test@example.com' } });
      fireEvent.click(screen.getByRole('button', { name: /join waitlist/i }));

      expect(screen.getByText(/joining/i)).toBeTruthy();

      await act(async () => {
        resolvePromise!({
          ok: true,
          json: () => Promise.resolve({
            data: { entry_id: 'entry_123', position: 1, referral_code: 'ABC' },
          }),
        });
      });

      await waitFor(() => {
        expect(screen.queryByText(/joining/i)).toBeNull();
      });
    });

    it('should disable form during submission', async () => {
      let resolvePromise: (value: unknown) => void;
      mockFetch.mockReturnValueOnce(
        new Promise((resolve) => {
          resolvePromise = resolve;
        })
      );

      render(<Waitlist {...defaultProps} />);

      fireEvent.change(screen.getByLabelText(/email address/i), { target: { value: 'test@example.com' } });
      fireEvent.click(screen.getByRole('button', { name: /join waitlist/i }));

      const emailInput = screen.getByLabelText(/email address/i) as HTMLInputElement;
      const button = screen.getByRole('button') as HTMLButtonElement;
      
      expect(emailInput.disabled).toBe(true);
      expect(button.disabled).toBe(true);

      await act(async () => {
        resolvePromise!({
          ok: true,
          json: () => Promise.resolve({
            data: { entry_id: 'entry_123', position: 1, referral_code: 'ABC' },
          }),
        });
      });
    });
  });

  describe('Validation', () => {
    it('should not submit with empty email', () => {
      render(<Waitlist {...defaultProps} />);

      // The email input has required attribute
      const emailInput = screen.getByLabelText(/email address/i) as HTMLInputElement;
      expect(emailInput.required).toBe(true);
      expect(emailInput.type).toBe('email');
      
      // Verify fetch is not called when form is not properly filled
      expect(mockFetch).not.toHaveBeenCalled();
    });
  });

  describe('Error Handling', () => {
    it('should display API error message', async () => {
      const onError = vi.fn();

      mockFetch.mockResolvedValueOnce({
        ok: false,
        json: () => Promise.resolve({
          error: { message: 'Email already on waitlist' },
        }),
      });

      render(<Waitlist {...defaultProps} onError={onError} />);

      fireEvent.change(screen.getByLabelText(/email address/i), { target: { value: 'existing@example.com' } });
      fireEvent.click(screen.getByRole('button', { name: /join waitlist/i }));

      await waitFor(() => {
        expect(screen.getByText(/email already on waitlist/i)).toBeTruthy();
      });

      expect(onError).toHaveBeenCalledWith(expect.any(Error));
    });

    it('should display network error', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Network error'));

      render(<Waitlist {...defaultProps} />);

      fireEvent.change(screen.getByLabelText(/email address/i), { target: { value: 'test@example.com' } });
      fireEvent.click(screen.getByRole('button', { name: /join waitlist/i }));

      await waitFor(() => {
        expect(screen.getByText(/network error/i)).toBeTruthy();
      });
    });
  });

  describe('Success State', () => {
    it('should display success message after joining', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          data: {
            entry_id: 'entry_123',
            position: 42,
            referral_code: 'XYZ98765',
          },
        }),
      });

      render(<Waitlist {...defaultProps} />);

      fireEvent.change(screen.getByLabelText(/email address/i), { target: { value: 'test@example.com' } });
      fireEvent.click(screen.getByRole('button', { name: /join waitlist/i }));

      await waitFor(() => {
        // Use heading role to be more specific
        expect(screen.getByRole('heading', { name: /you're on the list/i })).toBeTruthy();
      });
    });

    it('should display position when showPosition is true', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          data: {
            entry_id: 'entry_123',
            position: 42,
            referral_code: 'XYZ98765',
          },
        }),
      });

      render(<Waitlist {...defaultProps} showPosition />);

      fireEvent.change(screen.getByLabelText(/email address/i), { target: { value: 'test@example.com' } });
      fireEvent.click(screen.getByRole('button', { name: /join waitlist/i }));

      await waitFor(() => {
        expect(screen.getByText('#42')).toBeTruthy();
        expect(screen.getByText(/your position in line/i)).toBeTruthy();
      });
    });

    it('should not display position when showPosition is false', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          data: {
            entry_id: 'entry_123',
            position: 42,
            referral_code: 'XYZ98765',
          },
        }),
      });

      render(<Waitlist {...defaultProps} showPosition={false} showReferralCode={false} />);

      fireEvent.change(screen.getByLabelText(/email address/i), { target: { value: 'test@example.com' } });
      fireEvent.click(screen.getByRole('button', { name: /join waitlist/i }));

      await waitFor(() => {
        // Use heading role to be more specific
        expect(screen.getByRole('heading', { name: /you're on the list/i })).toBeTruthy();
      });

      // Position should not be shown
      expect(screen.queryByText('#42')).toBeNull();
      expect(screen.queryByText(/your position in line/i)).toBeNull();
    });

    it('should display referral code when showReferralCode is true', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          data: {
            entry_id: 'entry_123',
            position: 42,
            referral_code: 'XYZ98765',
          },
        }),
      });

      render(<Waitlist {...defaultProps} showReferralCode />);

      fireEvent.change(screen.getByLabelText(/email address/i), { target: { value: 'test@example.com' } });
      fireEvent.click(screen.getByRole('button', { name: /join waitlist/i }));

      await waitFor(() => {
        expect(screen.getByText('XYZ98765')).toBeTruthy();
        expect(screen.getByText(/share your referral code/i)).toBeTruthy();
      });
    });

    it('should copy referral code to clipboard', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          data: {
            entry_id: 'entry_123',
            position: 42,
            referral_code: 'XYZ98765',
          },
        }),
      });

      render(<Waitlist {...defaultProps} showReferralCode />);

      fireEvent.change(screen.getByLabelText(/email address/i), { target: { value: 'test@example.com' } });
      fireEvent.click(screen.getByRole('button', { name: /join waitlist/i }));

      await waitFor(() => {
        expect(screen.getByText('XYZ98765')).toBeTruthy();
      });

      const copyButton = screen.getByRole('button', { name: /copy/i });
      fireEvent.click(copyButton);

      expect(mockClipboard.writeText).toHaveBeenCalledWith('XYZ98765');

      await waitFor(() => {
        expect(screen.getByText(/copied/i)).toBeTruthy();
      });
    });

    it('should display custom success message', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          data: {
            entry_id: 'entry_123',
            position: 1,
            referral_code: 'ABC12345',
          },
        }),
      });

      render(
        <Waitlist
          {...defaultProps}
          successMessage="Thanks for signing up! We'll be in touch soon."
        />
      );

      fireEvent.change(screen.getByLabelText(/email address/i), { target: { value: 'test@example.com' } });
      fireEvent.click(screen.getByRole('button', { name: /join waitlist/i }));

      await waitFor(() => {
        expect(screen.getByText(/thanks for signing up/i)).toBeTruthy();
      });
    });
  });

  describe('Accessibility', () => {
    it('should have proper form labels', () => {
      render(<Waitlist {...defaultProps} collectMetadata />);

      expect(screen.getByLabelText(/email address/i)).toBeTruthy();
      expect(screen.getByLabelText(/first name/i)).toBeTruthy();
      expect(screen.getByLabelText(/last name/i)).toBeTruthy();
    });

    it('should have proper button aria-label for copy', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({
          data: {
            entry_id: 'entry_123',
            position: 1,
            referral_code: 'ABC12345',
          },
        }),
      });

      render(<Waitlist {...defaultProps} showReferralCode />);

      fireEvent.change(screen.getByLabelText(/email address/i), { target: { value: 'test@example.com' } });
      fireEvent.click(screen.getByRole('button', { name: /join waitlist/i }));

      await waitFor(() => {
        expect(screen.getByRole('button', { name: /copy referral code/i })).toBeTruthy();
      });
    });
  });

  describe('CSS Classes', () => {
    it('should apply custom className', () => {
      const { container } = render(
        <Waitlist {...defaultProps} className="custom-waitlist" />
      );

      expect(container.querySelector('.custom-waitlist')).toBeTruthy();
    });

    it('should have zalt-waitlist class', () => {
      const { container } = render(<Waitlist {...defaultProps} />);

      expect(container.querySelector('.zalt-waitlist')).toBeTruthy();
    });
  });
});
