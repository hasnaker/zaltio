/**
 * ImpersonationBanner Component Tests
 * @zalt/react
 * 
 * Tests for the ImpersonationBanner component.
 * Validates: Requirement 6.4 (Impersonation visual indicator)
 */

import React from 'react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import type { ImpersonationSession, RestrictedAction } from '../../hooks/useImpersonation';

// ============================================================================
// Mock Data
// ============================================================================

const mockImpersonationSession: ImpersonationSession = {
  id: 'imp_123',
  admin_id: 'admin_456',
  admin_email: 'admin@example.com',
  target_user_id: 'user_789',
  target_user_email: 'user@example.com',
  status: 'active',
  restricted_actions: ['change_password', 'delete_account', 'change_email'] as RestrictedAction[],
  started_at: new Date().toISOString(),
  expires_at: new Date(Date.now() + 3600000).toISOString(), // 1 hour from now
  reason: 'Customer support request',
};

// ============================================================================
// Mock Setup
// ============================================================================

const mockEndImpersonation = vi.fn().mockResolvedValue(undefined);
const mockRefresh = vi.fn().mockResolvedValue(undefined);
const mockIsActionRestricted = vi.fn().mockReturnValue(false);

const createMockReturn = (overrides = {}) => ({
  isImpersonating: true,
  session: mockImpersonationSession,
  remainingSeconds: 3600,
  remainingTimeFormatted: '60:00',
  restrictedActions: ['change_password', 'delete_account', 'change_email'] as RestrictedAction[],
  isActionRestricted: mockIsActionRestricted,
  endImpersonation: mockEndImpersonation,
  isLoading: false,
  error: null,
  refresh: mockRefresh,
  ...overrides,
});

vi.mock('../../hooks/useImpersonation', () => ({
  useImpersonation: vi.fn(() => createMockReturn()),
}));

import { ImpersonationBanner, type ImpersonationBannerProps } from '../ImpersonationBanner';
import { useImpersonation } from '../../hooks/useImpersonation';

// ============================================================================
// Test Setup
// ============================================================================

describe('ImpersonationBanner', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockEndImpersonation.mockResolvedValue(undefined);
    (useImpersonation as ReturnType<typeof vi.fn>).mockReturnValue(createMockReturn());
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  const renderBanner = (props: Partial<ImpersonationBannerProps> = {}) => {
    const defaultProps: ImpersonationBannerProps = {
      accessToken: 'test-token',
      apiUrl: '/api',
      ...props,
    };
    return render(<ImpersonationBanner {...defaultProps} />);
  };

  // ============================================================================
  // Rendering Tests
  // ============================================================================

  describe('Rendering', () => {
    it('should render banner when impersonating', () => {
      renderBanner();
      expect(screen.getByTestId('impersonation-banner')).toBeDefined();
      expect(screen.getByText('Impersonation Mode')).toBeDefined();
    });

    it('should not render when not impersonating', () => {
      (useImpersonation as ReturnType<typeof vi.fn>).mockReturnValue(createMockReturn({
        isImpersonating: false,
        session: null,
      }));
      renderBanner();
      expect(screen.queryByTestId('impersonation-banner')).toBeNull();
    });

    it('should display impersonated user email', () => {
      renderBanner();
      expect(screen.getByText('user@example.com')).toBeDefined();
    });

    it('should display admin email when showAdminInfo is true', () => {
      renderBanner({ showAdminInfo: true });
      expect(screen.getByText(/admin@example.com/)).toBeDefined();
    });

    it('should not display admin info when showAdminInfo is false', () => {
      renderBanner({ showAdminInfo: false });
      expect(screen.queryByText(/admin@example.com/)).toBeNull();
    });

    it('should display reason when showReason is true', () => {
      renderBanner({ showReason: true });
      expect(screen.getByText(/Customer support request/)).toBeDefined();
    });

    it('should not display reason when showReason is false', () => {
      renderBanner({ showReason: false });
      expect(screen.queryByText(/Customer support request/)).toBeNull();
    });

    it('should display end impersonation button', () => {
      renderBanner();
      expect(screen.getByTestId('end-impersonation-button')).toBeDefined();
      expect(screen.getByText('End Session')).toBeDefined();
    });
  });

  // ============================================================================
  // Timer Tests
  // ============================================================================

  describe('Timer', () => {
    it('should display countdown timer when showTimer is true', () => {
      renderBanner({ showTimer: true });
      expect(screen.getByText('60:00')).toBeDefined();
    });

    it('should not display timer when showTimer is false', () => {
      renderBanner({ showTimer: false });
      expect(screen.queryByText('60:00')).toBeNull();
    });

    it('should use custom timer renderer when provided', () => {
      const customRenderer = (seconds: number, formatted: string) => (
        <span data-testid="custom-timer">Custom: {formatted}</span>
      );
      renderBanner({ showTimer: true, renderTimer: customRenderer });
      expect(screen.getByTestId('custom-timer')).toBeDefined();
      expect(screen.getByText(/Custom: 60:00/)).toBeDefined();
    });
  });

  // ============================================================================
  // Restricted Actions Tests
  // ============================================================================

  describe('Restricted Actions', () => {
    it('should display restricted actions when showRestrictions is true', () => {
      renderBanner({ showRestrictions: true });
      expect(screen.getByText('Restricted:')).toBeDefined();
      expect(screen.getByText('Password')).toBeDefined();
      expect(screen.getByText('Delete')).toBeDefined();
      expect(screen.getByText('Email')).toBeDefined();
    });

    it('should not display restricted actions when showRestrictions is false', () => {
      renderBanner({ showRestrictions: false });
      expect(screen.queryByText('Restricted:')).toBeNull();
    });
  });

  // ============================================================================
  // End Impersonation Tests
  // ============================================================================

  describe('End Impersonation', () => {
    it('should call endImpersonation when button is clicked', async () => {
      renderBanner();
      const button = screen.getByTestId('end-impersonation-button');
      fireEvent.click(button);
      await waitFor(() => {
        expect(mockEndImpersonation).toHaveBeenCalled();
      });
    });

    it('should show loading state while ending impersonation', async () => {
      (useImpersonation as ReturnType<typeof vi.fn>).mockReturnValue(createMockReturn({
        isLoading: true,
      }));
      renderBanner();
      const button = screen.getByTestId('end-impersonation-button');
      expect(button).toHaveProperty('disabled', true);
    });

    it('should display error when present', () => {
      (useImpersonation as ReturnType<typeof vi.fn>).mockReturnValue(createMockReturn({
        error: 'Failed to end impersonation',
      }));
      renderBanner();
      expect(screen.getByText('Failed to end impersonation')).toBeDefined();
    });
  });

  // ============================================================================
  // Position and Variant Tests
  // ============================================================================

  describe('Position and Variant', () => {
    it('should render at top position by default', () => {
      renderBanner({ position: 'top' });
      const banner = screen.getByTestId('impersonation-banner');
      expect(banner.style.top).toBe('0px');
    });

    it('should render at bottom position when specified', () => {
      renderBanner({ position: 'bottom' });
      const banner = screen.getByTestId('impersonation-banner');
      expect(banner.style.bottom).toBe('0px');
    });

    it('should apply custom className', () => {
      const { container } = renderBanner({ className: 'custom-class' });
      expect(container.querySelector('.custom-class')).toBeDefined();
    });

    it('should apply custom zIndex', () => {
      renderBanner({ zIndex: 10000 });
      const banner = screen.getByTestId('impersonation-banner');
      expect(banner.style.zIndex).toBe('10000');
    });
  });

  // ============================================================================
  // Custom Labels Tests
  // ============================================================================

  describe('Custom Labels', () => {
    it('should use custom title label', () => {
      renderBanner({ labels: { title: 'Custom Title' } });
      expect(screen.getByText('Custom Title')).toBeDefined();
    });

    it('should use custom end button label', () => {
      renderBanner({ labels: { endButton: 'Exit Impersonation' } });
      expect(screen.getByText('Exit Impersonation')).toBeDefined();
    });

    it('should use custom impersonating label', () => {
      renderBanner({ labels: { impersonating: 'Acting as' } });
      expect(screen.getByText('Acting as:')).toBeDefined();
    });
  });

  // ============================================================================
  // Custom Renderers Tests
  // ============================================================================

  describe('Custom Renderers', () => {
    it('should use custom user info renderer', () => {
      const customRenderer = (session: ImpersonationSession) => (
        <span data-testid="custom-user-info">Custom User: {session.target_user_email}</span>
      );
      renderBanner({ renderUserInfo: customRenderer });
      expect(screen.getByTestId('custom-user-info')).toBeDefined();
      expect(screen.getByText(/Custom User: user@example.com/)).toBeDefined();
    });

    it('should use custom admin info renderer', () => {
      const customRenderer = (session: ImpersonationSession) => (
        <span data-testid="custom-admin-info">Admin: {session.admin_email}</span>
      );
      renderBanner({ showAdminInfo: true, renderAdminInfo: customRenderer });
      expect(screen.getByTestId('custom-admin-info')).toBeDefined();
    });
  });

  // ============================================================================
  // Compact Mode Tests
  // ============================================================================

  describe('Compact Mode', () => {
    it('should render in compact mode when specified', () => {
      renderBanner({ compact: true });
      const banner = screen.getByTestId('impersonation-banner');
      expect(banner.style.padding).toBe('8px 16px');
    });
  });

  // ============================================================================
  // Expired Session Tests
  // ============================================================================

  describe('Expired Session', () => {
    it('should show expired badge when session is expired', () => {
      (useImpersonation as ReturnType<typeof vi.fn>).mockReturnValue(createMockReturn({
        session: { ...mockImpersonationSession, status: 'expired' },
        remainingSeconds: 0,
      }));
      renderBanner();
      expect(screen.getByText('Session Expired')).toBeDefined();
    });

    it('should not show timer when session is expired', () => {
      (useImpersonation as ReturnType<typeof vi.fn>).mockReturnValue(createMockReturn({
        session: { ...mockImpersonationSession, status: 'expired' },
        remainingSeconds: 0,
        remainingTimeFormatted: '00:00',
      }));
      renderBanner({ showTimer: true });
      // Timer should not be visible when expired
      expect(screen.queryByText('00:00')).toBeNull();
    });
  });

  // ============================================================================
  // Accessibility Tests
  // ============================================================================

  describe('Accessibility', () => {
    it('should have role="alert"', () => {
      renderBanner();
      const banner = screen.getByTestId('impersonation-banner');
      expect(banner.getAttribute('role')).toBe('alert');
    });

    it('should have aria-live="polite"', () => {
      renderBanner();
      const banner = screen.getByTestId('impersonation-banner');
      expect(banner.getAttribute('aria-live')).toBe('polite');
    });

    it('should have accessible button label', () => {
      renderBanner();
      const button = screen.getByTestId('end-impersonation-button');
      expect(button.getAttribute('aria-label')).toBe('End Session');
    });

    it('should have accessible timer label', () => {
      renderBanner({ showTimer: true });
      const timer = screen.getByTitle('Time remaining');
      expect(timer.getAttribute('aria-label')).toContain('Time remaining');
    });
  });

  // ============================================================================
  // Fixed Position Tests
  // ============================================================================

  describe('Fixed Position', () => {
    it('should render as fixed position by default', () => {
      renderBanner();
      const banner = screen.getByTestId('impersonation-banner');
      expect(banner.style.position).toBe('fixed');
    });

    it('should render as relative position when fixed is false', () => {
      renderBanner({ fixed: false });
      const banner = screen.getByTestId('impersonation-banner');
      expect(banner.style.position).toBe('relative');
    });
  });

  // ============================================================================
  // hideWhenNotImpersonating Tests
  // ============================================================================

  describe('hideWhenNotImpersonating', () => {
    it('should hide when not impersonating and hideWhenNotImpersonating is true', () => {
      (useImpersonation as ReturnType<typeof vi.fn>).mockReturnValue(createMockReturn({
        isImpersonating: false,
        session: null,
      }));
      renderBanner({ hideWhenNotImpersonating: true });
      expect(screen.queryByTestId('impersonation-banner')).toBeNull();
    });

    it('should still hide when not impersonating even if hideWhenNotImpersonating is false', () => {
      (useImpersonation as ReturnType<typeof vi.fn>).mockReturnValue(createMockReturn({
        isImpersonating: false,
        session: null,
      }));
      renderBanner({ hideWhenNotImpersonating: false });
      // No session data means no banner
      expect(screen.queryByTestId('impersonation-banner')).toBeNull();
    });
  });

  // ============================================================================
  // Callback Tests
  // ============================================================================

  describe('Callbacks', () => {
    it('should pass onImpersonationEnd to hook', () => {
      const onImpersonationEnd = vi.fn();
      renderBanner({ onImpersonationEnd });
      expect(useImpersonation).toHaveBeenCalledWith(
        expect.objectContaining({ onImpersonationEnd })
      );
    });

    it('should pass onImpersonationExpire to hook', () => {
      const onImpersonationExpire = vi.fn();
      renderBanner({ onImpersonationExpire });
      expect(useImpersonation).toHaveBeenCalledWith(
        expect.objectContaining({ onImpersonationExpire })
      );
    });

    it('should pass enablePolling to hook', () => {
      renderBanner({ enablePolling: true, pollingInterval: 5000 });
      expect(useImpersonation).toHaveBeenCalledWith(
        expect.objectContaining({ enablePolling: true, pollingInterval: 5000 })
      );
    });
  });

  // ============================================================================
  // Viewing As Label Tests
  // ============================================================================

  describe('Viewing As Label', () => {
    it('should display default viewing as label', () => {
      renderBanner();
      expect(screen.getByText('Viewing as:')).toBeDefined();
    });
  });
});
