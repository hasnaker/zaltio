/**
 * ReverificationModal Component Tests
 * @zalt/react
 * 
 * Tests for the ReverificationModal component - step-up authentication UI.
 * Validates: Requirement 3.6 (Reverification UI Component)
 */

import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ReverificationModal } from '../ReverificationModal';

// Mock handlers
const mockOnPasswordSubmit = vi.fn();
const mockOnMFASubmit = vi.fn();
const mockOnWebAuthnSubmit = vi.fn();
const mockOnClose = vi.fn();

describe('ReverificationModal', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockOnPasswordSubmit.mockResolvedValue(undefined);
    mockOnMFASubmit.mockResolvedValue(undefined);
    mockOnWebAuthnSubmit.mockResolvedValue(undefined);
  });

  describe('rendering', () => {
    it('should not render when isOpen is false', () => {
      render(
        <ReverificationModal
          isOpen={false}
          onPasswordSubmit={mockOnPasswordSubmit}
          onClose={mockOnClose}
        />
      );
      expect(screen.queryByTestId('reverification-modal')).toBeNull();
    });

    it('should render when isOpen is true', () => {
      render(
        <ReverificationModal
          isOpen={true}
          onPasswordSubmit={mockOnPasswordSubmit}
          onClose={mockOnClose}
        />
      );
      expect(screen.getByTestId('reverification-modal')).toBeDefined();
    });

    it('should render default title and subtitle', () => {
      render(
        <ReverificationModal
          isOpen={true}
          onPasswordSubmit={mockOnPasswordSubmit}
          onClose={mockOnClose}
        />
      );
      expect(screen.getByText('Verify Your Identity')).toBeDefined();
      expect(screen.getByText('This action requires additional verification for security.')).toBeDefined();
    });

    it('should render custom title and subtitle', () => {
      render(
        <ReverificationModal
          isOpen={true}
          title="Custom Title"
          subtitle="Custom subtitle text"
          onPasswordSubmit={mockOnPasswordSubmit}
          onClose={mockOnClose}
        />
      );
      expect(screen.getByText('Custom Title')).toBeDefined();
      expect(screen.getByText('Custom subtitle text')).toBeDefined();
    });

    it('should show close button by default', () => {
      render(
        <ReverificationModal
          isOpen={true}
          onPasswordSubmit={mockOnPasswordSubmit}
          onClose={mockOnClose}
        />
      );
      expect(screen.getByLabelText('Close')).toBeDefined();
    });

    it('should hide close button when showCloseButton is false', () => {
      render(
        <ReverificationModal
          isOpen={true}
          showCloseButton={false}
          onPasswordSubmit={mockOnPasswordSubmit}
          onClose={mockOnClose}
        />
      );
      expect(screen.queryByLabelText('Close')).toBeNull();
    });
  });


  describe('password form', () => {
    it('should render password form by default', () => {
      render(
        <ReverificationModal
          isOpen={true}
          onPasswordSubmit={mockOnPasswordSubmit}
          onClose={mockOnClose}
        />
      );
      expect(screen.getByTestId('password-form')).toBeDefined();
      expect(screen.getByLabelText('Password')).toBeDefined();
    });

    it('should disable submit button when password is empty', () => {
      render(
        <ReverificationModal
          isOpen={true}
          onPasswordSubmit={mockOnPasswordSubmit}
          onClose={mockOnClose}
        />
      );
      const submitButton = screen.getByLabelText('Verify');
      expect(submitButton).toHaveProperty('disabled', true);
    });

    it('should enable submit button when password is entered', () => {
      render(
        <ReverificationModal
          isOpen={true}
          onPasswordSubmit={mockOnPasswordSubmit}
          onClose={mockOnClose}
        />
      );
      const input = screen.getByLabelText('Password');
      fireEvent.change(input, { target: { value: 'testpassword' } });
      const submitButton = screen.getByLabelText('Verify');
      expect(submitButton).toHaveProperty('disabled', false);
    });

    it('should call onPasswordSubmit when form is submitted', async () => {
      render(
        <ReverificationModal
          isOpen={true}
          onPasswordSubmit={mockOnPasswordSubmit}
          onClose={mockOnClose}
        />
      );
      const input = screen.getByLabelText('Password');
      fireEvent.change(input, { target: { value: 'testpassword' } });
      const submitButton = screen.getByLabelText('Verify');
      fireEvent.click(submitButton);
      await waitFor(() => {
        expect(mockOnPasswordSubmit).toHaveBeenCalledWith('testpassword');
      });
    });

    it('should show error message when error prop is set', () => {
      render(
        <ReverificationModal
          isOpen={true}
          error="Invalid password"
          onPasswordSubmit={mockOnPasswordSubmit}
          onClose={mockOnClose}
        />
      );
      expect(screen.getByText('Invalid password')).toBeDefined();
    });

    it('should show loading state when isLoading is true', () => {
      render(
        <ReverificationModal
          isOpen={true}
          isLoading={true}
          onPasswordSubmit={mockOnPasswordSubmit}
          onClose={mockOnClose}
        />
      );
      expect(screen.getByText('Verifying...')).toBeDefined();
    });
  });

  describe('MFA form', () => {
    it('should render MFA form when mfa method is selected', () => {
      render(
        <ReverificationModal
          isOpen={true}
          requiredLevel="password"
          defaultMethod="mfa"
          onMFASubmit={mockOnMFASubmit}
          onClose={mockOnClose}
        />
      );
      expect(screen.getByTestId('mfa-form')).toBeDefined();
      expect(screen.getByLabelText('MFA code')).toBeDefined();
    });

    it('should only allow 6 digits in MFA input', () => {
      render(
        <ReverificationModal
          isOpen={true}
          defaultMethod="mfa"
          onMFASubmit={mockOnMFASubmit}
          onClose={mockOnClose}
        />
      );
      const input = screen.getByLabelText('MFA code');
      fireEvent.change(input, { target: { value: '123456789' } });
      expect(input).toHaveProperty('value', '123456');
    });

    it('should filter non-numeric characters from MFA input', () => {
      render(
        <ReverificationModal
          isOpen={true}
          defaultMethod="mfa"
          onMFASubmit={mockOnMFASubmit}
          onClose={mockOnClose}
        />
      );
      const input = screen.getByLabelText('MFA code');
      fireEvent.change(input, { target: { value: '12ab34' } });
      expect(input).toHaveProperty('value', '1234');
    });

    it('should disable submit button when code is not 6 digits', () => {
      render(
        <ReverificationModal
          isOpen={true}
          defaultMethod="mfa"
          onMFASubmit={mockOnMFASubmit}
          onClose={mockOnClose}
        />
      );
      const input = screen.getByLabelText('MFA code');
      fireEvent.change(input, { target: { value: '12345' } });
      const submitButton = screen.getByLabelText('Verify');
      expect(submitButton).toHaveProperty('disabled', true);
    });

    it('should enable submit button when code is 6 digits', () => {
      render(
        <ReverificationModal
          isOpen={true}
          defaultMethod="mfa"
          onMFASubmit={mockOnMFASubmit}
          onClose={mockOnClose}
        />
      );
      const input = screen.getByLabelText('MFA code');
      fireEvent.change(input, { target: { value: '123456' } });
      const submitButton = screen.getByLabelText('Verify');
      expect(submitButton).toHaveProperty('disabled', false);
    });

    it('should call onMFASubmit when form is submitted', async () => {
      render(
        <ReverificationModal
          isOpen={true}
          defaultMethod="mfa"
          onMFASubmit={mockOnMFASubmit}
          onClose={mockOnClose}
        />
      );
      const input = screen.getByLabelText('MFA code');
      fireEvent.change(input, { target: { value: '123456' } });
      const submitButton = screen.getByLabelText('Verify');
      fireEvent.click(submitButton);
      await waitFor(() => {
        expect(mockOnMFASubmit).toHaveBeenCalledWith('123456');
      });
    });
  });


  describe('WebAuthn form', () => {
    it('should render WebAuthn form when webauthn method is selected', () => {
      render(
        <ReverificationModal
          isOpen={true}
          defaultMethod="webauthn"
          onWebAuthnSubmit={mockOnWebAuthnSubmit}
          onClose={mockOnClose}
        />
      );
      expect(screen.getByTestId('webauthn-form')).toBeDefined();
    });

    it('should call onWebAuthnSubmit when button is clicked', async () => {
      render(
        <ReverificationModal
          isOpen={true}
          defaultMethod="webauthn"
          onWebAuthnSubmit={mockOnWebAuthnSubmit}
          onClose={mockOnClose}
        />
      );
      const submitButton = screen.getByLabelText('Use Passkey');
      fireEvent.click(submitButton);
      await waitFor(() => {
        expect(mockOnWebAuthnSubmit).toHaveBeenCalled();
      });
    });

    it('should show loading state for WebAuthn', () => {
      render(
        <ReverificationModal
          isOpen={true}
          isLoading={true}
          defaultMethod="webauthn"
          onWebAuthnSubmit={mockOnWebAuthnSubmit}
          onClose={mockOnClose}
        />
      );
      expect(screen.getByText('Waiting for passkey...')).toBeDefined();
    });
  });

  describe('method tabs', () => {
    it('should show method tabs when multiple methods are available', () => {
      render(
        <ReverificationModal
          isOpen={true}
          requiredLevel="password"
          onPasswordSubmit={mockOnPasswordSubmit}
          onMFASubmit={mockOnMFASubmit}
          onWebAuthnSubmit={mockOnWebAuthnSubmit}
          onClose={mockOnClose}
        />
      );
      expect(screen.getByText('Password')).toBeDefined();
      expect(screen.getByText('Authenticator')).toBeDefined();
      expect(screen.getByText('Passkey')).toBeDefined();
    });

    it('should switch forms when method tab is clicked', async () => {
      render(
        <ReverificationModal
          isOpen={true}
          requiredLevel="password"
          onPasswordSubmit={mockOnPasswordSubmit}
          onMFASubmit={mockOnMFASubmit}
          onWebAuthnSubmit={mockOnWebAuthnSubmit}
          onClose={mockOnClose}
        />
      );
      // Initially shows password form
      expect(screen.getByTestId('password-form')).toBeDefined();
      
      // Click MFA tab using act to ensure state updates
      const mfaTab = screen.getByText('Authenticator');
      await act(async () => {
        fireEvent.click(mfaTab);
      });
      
      // Should now show MFA form
      expect(screen.getByTestId('mfa-form')).toBeDefined();
      expect(screen.queryByTestId('password-form')).toBeNull();
    });

    it('should only show webauthn when requiredLevel is webauthn', () => {
      render(
        <ReverificationModal
          isOpen={true}
          requiredLevel="webauthn"
          onWebAuthnSubmit={mockOnWebAuthnSubmit}
          onClose={mockOnClose}
        />
      );
      // Should not show tabs since only one method
      expect(screen.queryByText('Password')).toBeNull();
      expect(screen.queryByText('Authenticator')).toBeNull();
      // Should show WebAuthn form directly
      expect(screen.getByTestId('webauthn-form')).toBeDefined();
    });

    it('should show mfa and webauthn when requiredLevel is mfa', () => {
      render(
        <ReverificationModal
          isOpen={true}
          requiredLevel="mfa"
          onMFASubmit={mockOnMFASubmit}
          onWebAuthnSubmit={mockOnWebAuthnSubmit}
          onClose={mockOnClose}
        />
      );
      expect(screen.getByText('Authenticator')).toBeDefined();
      expect(screen.getByText('Passkey')).toBeDefined();
      expect(screen.queryByText('Password')).toBeNull();
    });

    it('should use custom availableMethods when provided', () => {
      render(
        <ReverificationModal
          isOpen={true}
          availableMethods={['password', 'webauthn']}
          onPasswordSubmit={mockOnPasswordSubmit}
          onWebAuthnSubmit={mockOnWebAuthnSubmit}
          onClose={mockOnClose}
        />
      );
      expect(screen.getByText('Password')).toBeDefined();
      expect(screen.getByText('Passkey')).toBeDefined();
      expect(screen.queryByText('Authenticator')).toBeNull();
    });
  });

  describe('close behavior', () => {
    it('should call onClose when close button is clicked', () => {
      render(
        <ReverificationModal
          isOpen={true}
          onPasswordSubmit={mockOnPasswordSubmit}
          onClose={mockOnClose}
        />
      );
      const closeButton = screen.getByLabelText('Close');
      fireEvent.click(closeButton);
      expect(mockOnClose).toHaveBeenCalled();
    });

    it('should call onClose when cancel button is clicked', () => {
      render(
        <ReverificationModal
          isOpen={true}
          onPasswordSubmit={mockOnPasswordSubmit}
          onClose={mockOnClose}
        />
      );
      const cancelButton = screen.getByLabelText('Cancel');
      fireEvent.click(cancelButton);
      expect(mockOnClose).toHaveBeenCalled();
    });

    it('should call onClose when backdrop is clicked', () => {
      render(
        <ReverificationModal
          isOpen={true}
          closeOnBackdropClick={true}
          onPasswordSubmit={mockOnPasswordSubmit}
          onClose={mockOnClose}
        />
      );
      const overlay = screen.getByTestId('reverification-modal');
      fireEvent.click(overlay);
      expect(mockOnClose).toHaveBeenCalled();
    });

    it('should not call onClose when backdrop click is disabled', () => {
      render(
        <ReverificationModal
          isOpen={true}
          closeOnBackdropClick={false}
          onPasswordSubmit={mockOnPasswordSubmit}
          onClose={mockOnClose}
        />
      );
      const overlay = screen.getByTestId('reverification-modal');
      fireEvent.click(overlay);
      expect(mockOnClose).not.toHaveBeenCalled();
    });

    it('should call onClose when Escape key is pressed', () => {
      render(
        <ReverificationModal
          isOpen={true}
          closeOnEscape={true}
          onPasswordSubmit={mockOnPasswordSubmit}
          onClose={mockOnClose}
        />
      );
      fireEvent.keyDown(document, { key: 'Escape' });
      expect(mockOnClose).toHaveBeenCalled();
    });

    it('should not call onClose when Escape is disabled', () => {
      render(
        <ReverificationModal
          isOpen={true}
          closeOnEscape={false}
          onPasswordSubmit={mockOnPasswordSubmit}
          onClose={mockOnClose}
        />
      );
      fireEvent.keyDown(document, { key: 'Escape' });
      expect(mockOnClose).not.toHaveBeenCalled();
    });
  });


  describe('validity info', () => {
    it('should show validity period', () => {
      render(
        <ReverificationModal
          isOpen={true}
          validityMinutes={10}
          onPasswordSubmit={mockOnPasswordSubmit}
          onClose={mockOnClose}
        />
      );
      expect(screen.getByText('Verification will be valid for 10 minutes')).toBeDefined();
    });

    it('should show singular minute when validityMinutes is 1', () => {
      render(
        <ReverificationModal
          isOpen={true}
          validityMinutes={1}
          onPasswordSubmit={mockOnPasswordSubmit}
          onClose={mockOnClose}
        />
      );
      expect(screen.getByText('Verification will be valid for 1 minute')).toBeDefined();
    });

    it('should not show validity info when validityMinutes is null', () => {
      render(
        <ReverificationModal
          isOpen={true}
          validityMinutes={null}
          onPasswordSubmit={mockOnPasswordSubmit}
          onClose={mockOnClose}
        />
      );
      expect(screen.queryByText(/Verification will be valid/)).toBeNull();
    });
  });

  describe('custom labels', () => {
    it('should use custom labels', () => {
      render(
        <ReverificationModal
          isOpen={true}
          labels={{
            password: 'Şifre',
            mfa: 'Doğrulayıcı',
            webauthn: 'Geçiş Anahtarı',
            submit: 'Doğrula',
            cancel: 'İptal',
          }}
          onPasswordSubmit={mockOnPasswordSubmit}
          onMFASubmit={mockOnMFASubmit}
          onWebAuthnSubmit={mockOnWebAuthnSubmit}
          onClose={mockOnClose}
        />
      );
      expect(screen.getByText('Şifre')).toBeDefined();
      expect(screen.getByText('Doğrulayıcı')).toBeDefined();
      expect(screen.getByText('Geçiş Anahtarı')).toBeDefined();
      expect(screen.getByLabelText('Doğrula')).toBeDefined();
      expect(screen.getByLabelText('İptal')).toBeDefined();
    });
  });

  describe('accessibility', () => {
    it('should have proper ARIA attributes', () => {
      render(
        <ReverificationModal
          isOpen={true}
          onPasswordSubmit={mockOnPasswordSubmit}
          onClose={mockOnClose}
        />
      );
      const modal = screen.getByTestId('reverification-modal');
      expect(modal.getAttribute('role')).toBe('dialog');
      expect(modal.getAttribute('aria-modal')).toBe('true');
      expect(modal.getAttribute('aria-labelledby')).toBe('reverification-title');
      expect(modal.getAttribute('aria-describedby')).toBe('reverification-subtitle');
    });

    it('should have proper role for method tabs', () => {
      render(
        <ReverificationModal
          isOpen={true}
          requiredLevel="password"
          onPasswordSubmit={mockOnPasswordSubmit}
          onMFASubmit={mockOnMFASubmit}
          onClose={mockOnClose}
        />
      );
      const tablist = screen.getByRole('tablist');
      expect(tablist).toBeDefined();
      
      const tabs = screen.getAllByRole('tab');
      expect(tabs.length).toBeGreaterThan(1);
    });

    it('should have proper aria-selected on active tab', () => {
      render(
        <ReverificationModal
          isOpen={true}
          requiredLevel="password"
          onPasswordSubmit={mockOnPasswordSubmit}
          onMFASubmit={mockOnMFASubmit}
          onClose={mockOnClose}
        />
      );
      const passwordTab = screen.getByText('Password').closest('button');
      expect(passwordTab?.getAttribute('aria-selected')).toBe('true');
      
      const mfaTab = screen.getByText('Authenticator').closest('button');
      expect(mfaTab?.getAttribute('aria-selected')).toBe('false');
    });

    it('should show error with role alert', () => {
      render(
        <ReverificationModal
          isOpen={true}
          error="Test error"
          onPasswordSubmit={mockOnPasswordSubmit}
          onClose={mockOnClose}
        />
      );
      const errorElement = screen.getByRole('alert');
      expect(errorElement).toBeDefined();
      expect(errorElement.textContent).toContain('Test error');
    });
  });

  describe('custom className', () => {
    it('should apply custom className', () => {
      render(
        <ReverificationModal
          isOpen={true}
          className="custom-modal-class"
          onPasswordSubmit={mockOnPasswordSubmit}
          onClose={mockOnClose}
        />
      );
      const modal = screen.getByTestId('reverification-modal');
      expect(modal.classList.contains('custom-modal-class')).toBe(true);
    });
  });
});
