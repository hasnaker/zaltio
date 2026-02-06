/**
 * SessionTaskHandler Component Tests
 * @zalt/react
 * 
 * Tests for the SessionTaskHandler component - post-login task handling UI.
 * Validates: Requirement 4.6 (Session Task Handling UI)
 */

import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { SessionTaskHandler } from '../SessionTaskHandler';
import type { SessionTask } from '../../hooks/useSessionTasks';

// Mock fetch globally
const mockFetch = vi.fn();
global.fetch = mockFetch;

// Sample tasks for testing
const createMockTask = (overrides: Partial<SessionTask> = {}): SessionTask => ({
  id: 'task_123',
  session_id: 'session_456',
  type: 'reset_password',
  status: 'pending',
  metadata: { reason: 'compromised', message: 'Password must be reset' },
  created_at: '2026-01-25T10:00:00Z',
  priority: 1,
  blocking: true,
  ...overrides,
});

describe('SessionTaskHandler', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFetch.mockReset();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Rendering', () => {
    it('should render loading state initially', () => {
      mockFetch.mockImplementation(() => new Promise(() => {})); // Never resolves

      render(<SessionTaskHandler accessToken="test_token" />);
      
      expect(screen.getByText('Loading tasks...')).toBeDefined();
    });

    it('should render no tasks state when empty', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({ tasks: [] }),
      });

      render(<SessionTaskHandler accessToken="test_token" />);

      await waitFor(() => {
        expect(screen.getByText('All tasks completed!')).toBeDefined();
      });
    });

    it('should render task handler with default title', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({ tasks: [createMockTask()] }),
      });

      render(<SessionTaskHandler accessToken="test_token" />);

      await waitFor(() => {
        expect(screen.getByText('Complete Required Actions')).toBeDefined();
      });
    });

    it('should render custom title and subtitle', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({ tasks: [createMockTask()] }),
      });

      render(
        <SessionTaskHandler 
          accessToken="test_token"
          title="Custom Title"
          subtitle="Custom subtitle"
        />
      );

      await waitFor(() => {
        expect(screen.getByText('Custom Title')).toBeDefined();
        expect(screen.getByText('Custom subtitle')).toBeDefined();
      });
    });

    it('should apply custom className', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({ tasks: [createMockTask()] }),
      });

      render(
        <SessionTaskHandler 
          accessToken="test_token"
          className="custom-class"
        />
      );

      await waitFor(() => {
        const container = screen.getByTestId('session-task-handler');
        expect(container.classList.contains('custom-class')).toBe(true);
      });
    });

    it('should show blocking badge for blocking tasks', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({ tasks: [createMockTask({ blocking: true })] }),
      });

      render(<SessionTaskHandler accessToken="test_token" />);

      await waitFor(() => {
        expect(screen.getByText('Required')).toBeDefined();
      });
    });
  });

  describe('Password Reset Form', () => {
    it('should render password reset form for reset_password task', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({ tasks: [createMockTask({ type: 'reset_password' })] }),
      });

      render(<SessionTaskHandler accessToken="test_token" />);

      await waitFor(() => {
        expect(screen.getByTestId('password-reset-form')).toBeDefined();
        expect(screen.getByLabelText('New password')).toBeDefined();
        expect(screen.getByLabelText('Confirm password')).toBeDefined();
      });
    });

    it('should show compromised password warning', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({ 
          tasks: [createMockTask({ 
            type: 'reset_password',
            metadata: { reason: 'compromised' }
          })] 
        }),
      });

      render(<SessionTaskHandler accessToken="test_token" />);

      await waitFor(() => {
        expect(screen.getByText(/found in a data breach/)).toBeDefined();
      });
    });

    it('should validate password match', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({ tasks: [createMockTask({ type: 'reset_password' })] }),
      });

      render(<SessionTaskHandler accessToken="test_token" />);

      await waitFor(() => {
        expect(screen.getByTestId('password-reset-form')).toBeDefined();
      });

      const passwordInput = screen.getByLabelText('New password');
      const confirmInput = screen.getByLabelText('Confirm password');
      
      fireEvent.change(passwordInput, { target: { value: 'NewPassword123!' } });
      fireEvent.change(confirmInput, { target: { value: 'DifferentPassword!' } });
      
      const submitButton = screen.getByText('Update Password');
      fireEvent.click(submitButton);

      await waitFor(() => {
        expect(screen.getByText('Passwords do not match')).toBeDefined();
      });
    });
  });

  describe('MFA Setup Form', () => {
    it('should render MFA setup form for setup_mfa task', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({ 
          tasks: [createMockTask({ 
            type: 'setup_mfa',
            metadata: { message: 'MFA required by policy' }
          })] 
        }),
      });

      render(<SessionTaskHandler accessToken="test_token" />);

      await waitFor(() => {
        expect(screen.getByTestId('mfa-setup-form')).toBeDefined();
        expect(screen.getByText('MFA required by policy')).toBeDefined();
      });
    });

    it('should show MFA method options', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({ tasks: [createMockTask({ type: 'setup_mfa' })] }),
      });

      render(
        <SessionTaskHandler 
          accessToken="test_token"
          availableMfaMethods={['totp', 'webauthn']}
        />
      );

      await waitFor(() => {
        expect(screen.getByText('Authenticator App')).toBeDefined();
        expect(screen.getByText('Passkey')).toBeDefined();
      });
    });

    it('should only allow 6 digits in MFA code input', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({ tasks: [createMockTask({ type: 'setup_mfa' })] }),
      });

      render(<SessionTaskHandler accessToken="test_token" />);

      await waitFor(() => {
        expect(screen.getByTestId('mfa-setup-form')).toBeDefined();
      });

      const input = screen.getByLabelText('MFA code');
      fireEvent.change(input, { target: { value: '123456789' } });
      expect(input).toHaveProperty('value', '123456');
    });
  });

  describe('Organization Selector', () => {
    it('should render organization selector for choose_organization task', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({ 
          tasks: [createMockTask({ 
            type: 'choose_organization',
            metadata: {
              available_organizations: [
                { id: 'org_1', name: 'Organization 1', role: 'admin' },
                { id: 'org_2', name: 'Organization 2', role: 'member' },
              ],
              message: 'Select your organization',
            }
          })] 
        }),
      });

      render(<SessionTaskHandler accessToken="test_token" />);

      await waitFor(() => {
        expect(screen.getByTestId('organization-selector-form')).toBeDefined();
        expect(screen.getByText('Organization 1')).toBeDefined();
        expect(screen.getByText('Organization 2')).toBeDefined();
      });
    });
  });

  describe('Email Verification Form', () => {
    it('should render email verification form for verify_email task', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({ 
          tasks: [createMockTask({ 
            type: 'verify_email',
            metadata: { email: 'test@example.com' }
          })] 
        }),
      });

      render(<SessionTaskHandler accessToken="test_token" />);

      await waitFor(() => {
        expect(screen.getByTestId('email-verification-form')).toBeDefined();
        expect(screen.getByText(/test@example.com/)).toBeDefined();
      });
    });
  });

  describe('Terms Acceptance Form', () => {
    it('should render terms acceptance form for accept_terms task', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({ 
          tasks: [createMockTask({ 
            type: 'accept_terms',
            metadata: { 
              terms_url: 'https://example.com/terms',
              message: 'Please accept updated terms'
            }
          })] 
        }),
      });

      render(<SessionTaskHandler accessToken="test_token" />);

      await waitFor(() => {
        expect(screen.getByTestId('terms-acceptance-form')).toBeDefined();
        expect(screen.getByText('Please accept updated terms')).toBeDefined();
      });
    });

    it('should require checkbox to be checked', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({ tasks: [createMockTask({ type: 'accept_terms' })] }),
      });

      render(<SessionTaskHandler accessToken="test_token" />);

      await waitFor(() => {
        expect(screen.getByTestId('terms-acceptance-form')).toBeDefined();
      });

      const submitButton = screen.getByText('Accept & Continue');
      expect(submitButton).toHaveProperty('disabled', true);

      const checkbox = screen.getByLabelText('Accept terms of service');
      fireEvent.click(checkbox);

      expect(submitButton).toHaveProperty('disabled', false);
    });
  });

  describe('Skip Button', () => {
    it('should show skip button for non-blocking tasks', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({ 
          tasks: [createMockTask({ blocking: false, type: 'custom' })] 
        }),
      });

      render(<SessionTaskHandler accessToken="test_token" allowSkip={true} />);

      await waitFor(() => {
        expect(screen.getByText('Skip for now')).toBeDefined();
      });
    });

    it('should not show skip button for blocking tasks', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({ 
          tasks: [createMockTask({ blocking: true })] 
        }),
      });

      render(<SessionTaskHandler accessToken="test_token" allowSkip={true} />);

      await waitFor(() => {
        expect(screen.getByTestId('session-task-handler')).toBeDefined();
      });

      expect(screen.queryByText('Skip for now')).toBeNull();
    });
  });

  describe('Custom Renderers', () => {
    it('should use custom renderer when provided', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({ tasks: [createMockTask({ type: 'reset_password' })] }),
      });

      const customRenderer = vi.fn().mockReturnValue(
        <div data-testid="custom-renderer">Custom Password Reset</div>
      );

      render(
        <SessionTaskHandler 
          accessToken="test_token"
          customRenderers={{
            reset_password: customRenderer,
          }}
        />
      );

      await waitFor(() => {
        expect(screen.getByTestId('custom-renderer')).toBeDefined();
        expect(customRenderer).toHaveBeenCalled();
      });
    });
  });

  describe('Custom Loading and No Tasks Renderers', () => {
    it('should use custom loading renderer', () => {
      mockFetch.mockImplementation(() => new Promise(() => {}));

      render(
        <SessionTaskHandler 
          accessToken="test_token"
          renderLoading={() => <div data-testid="custom-loading">Custom Loading...</div>}
        />
      );

      expect(screen.getByTestId('custom-loading')).toBeDefined();
    });

    it('should use custom no tasks renderer', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({ tasks: [] }),
      });

      render(
        <SessionTaskHandler 
          accessToken="test_token"
          renderNoTasks={() => <div data-testid="custom-no-tasks">No tasks here!</div>}
        />
      );

      await waitFor(() => {
        expect(screen.getByTestId('custom-no-tasks')).toBeDefined();
      });
    });
  });

  describe('Callbacks', () => {
    it('should call onError when error occurs', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 500,
        json: async () => ({ error: { message: 'Server error' } }),
      });

      const onError = vi.fn();
      render(
        <SessionTaskHandler 
          accessToken="test_token"
          onError={onError}
        />
      );

      await waitFor(() => {
        expect(onError).toHaveBeenCalled();
      });
    });
  });

  describe('Custom Labels', () => {
    it('should use custom labels', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({ tasks: [createMockTask({ type: 'reset_password' })] }),
      });

      render(
        <SessionTaskHandler 
          accessToken="test_token"
          labels={{
            resetPassword: 'Şifre Sıfırla',
          }}
        />
      );

      await waitFor(() => {
        expect(screen.getByText('Şifre Sıfırla')).toBeDefined();
      });
    });
  });

  describe('Accessibility', () => {
    it('should have proper ARIA attributes', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({ tasks: [createMockTask()] }),
      });

      render(<SessionTaskHandler accessToken="test_token" />);

      await waitFor(() => {
        const container = screen.getByTestId('session-task-handler');
        expect(container.getAttribute('role')).toBe('main');
        expect(container.getAttribute('aria-label')).toBe('Session task handler');
      });
    });
  });
});
