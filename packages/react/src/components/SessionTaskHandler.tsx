/**
 * SessionTaskHandler Component
 * @zalt/react
 * 
 * Component for handling post-login session tasks.
 * Detects pending tasks and shows appropriate UI for each task type:
 * - reset_password: Password reset form
 * - setup_mfa: MFA setup wizard
 * - choose_organization: Organization selector
 * - verify_email: Email verification prompt
 * - accept_terms: Terms acceptance form
 * - custom: Custom task handler
 * 
 * Validates: Requirement 4.6 (Session Task Handling UI)
 */

'use client';

import React, { useState, useCallback, useEffect, useRef } from 'react';
import {
  useSessionTasks,
  type SessionTask,
  type SessionTaskType,
  type TaskCompletionData,
  type OrganizationOption,
  type UseSessionTasksOptions
} from '../hooks/useSessionTasks';

// ============================================================================
// Types
// ============================================================================

/**
 * SessionTaskHandler component props
 */
export interface SessionTaskHandlerProps {
  /** API base URL */
  apiUrl?: string;
  /** Access token for API calls */
  accessToken?: string;
  /** Auto-fetch tasks on mount */
  autoFetch?: boolean;
  /** Polling interval in milliseconds */
  pollingInterval?: number;
  /** Callback when task is completed */
  onTaskCompleted?: (task: SessionTask) => void;
  /** Callback when all tasks are completed */
  onAllTasksCompleted?: () => void;
  /** Callback on error */
  onError?: (error: Error) => void;
  /** Custom class name */
  className?: string;
  /** Custom title */
  title?: string;
  /** Custom subtitle */
  subtitle?: string;
  /** Show task progress indicator */
  showProgress?: boolean;
  /** Allow skipping non-blocking tasks */
  allowSkip?: boolean;
  /** Custom labels */
  labels?: {
    resetPassword?: string;
    setupMfa?: string;
    chooseOrganization?: string;
    verifyEmail?: string;
    acceptTerms?: string;
    submit?: string;
    skip?: string;
    loading?: string;
  };
  /** Custom renderers for task types */
  customRenderers?: {
    reset_password?: (props: TaskRendererProps) => React.ReactNode;
    setup_mfa?: (props: TaskRendererProps) => React.ReactNode;
    choose_organization?: (props: TaskRendererProps) => React.ReactNode;
    verify_email?: (props: TaskRendererProps) => React.ReactNode;
    accept_terms?: (props: TaskRendererProps) => React.ReactNode;
    custom?: (props: TaskRendererProps) => React.ReactNode;
  };
  /** Render when no tasks */
  renderNoTasks?: () => React.ReactNode;
  /** Render loading state */
  renderLoading?: () => React.ReactNode;
  /** Password validation function */
  validatePassword?: (password: string) => { valid: boolean; errors?: string[] };
  /** MFA methods available */
  availableMfaMethods?: ('totp' | 'webauthn')[];
  /** Redirect URL after all tasks completed */
  redirectUrl?: string;
}

/**
 * Props passed to custom task renderers
 */
export interface TaskRendererProps {
  task: SessionTask;
  onComplete: (data?: TaskCompletionData) => Promise<boolean>;
  onSkip?: () => Promise<boolean>;
  isLoading: boolean;
  error: string | null;
}

// ============================================================================
// Styles
// ============================================================================

const styles = {
  container: {
    background: 'var(--zalt-modal-bg, #1a1a2e)',
    borderRadius: 'var(--zalt-radius, 0.75rem)',
    padding: '24px',
    maxWidth: '480px',
    width: '100%',
    margin: '0 auto',
    boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.5)',
    border: '1px solid rgba(255, 255, 255, 0.1)',
    fontFamily: 'var(--zalt-font, system-ui, sans-serif)',
    color: 'var(--zalt-text, #fff)',
  } as React.CSSProperties,

  header: {
    marginBottom: '24px',
    textAlign: 'center' as const,
  } as React.CSSProperties,

  title: {
    fontSize: '24px',
    fontWeight: 600,
    margin: 0,
    marginBottom: '8px',
  } as React.CSSProperties,

  subtitle: {
    fontSize: '14px',
    color: 'rgba(255, 255, 255, 0.6)',
    margin: 0,
  } as React.CSSProperties,

  progress: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '8px',
    marginBottom: '20px',
    padding: '12px',
    background: 'rgba(255, 255, 255, 0.05)',
    borderRadius: 'var(--zalt-radius, 0.5rem)',
  } as React.CSSProperties,

  progressDot: {
    width: '8px',
    height: '8px',
    borderRadius: '50%',
    background: 'rgba(255, 255, 255, 0.3)',
  } as React.CSSProperties,

  progressDotActive: {
    background: 'var(--zalt-primary, #10b981)',
  } as React.CSSProperties,

  progressDotCompleted: {
    background: 'var(--zalt-success, #22c55e)',
  } as React.CSSProperties,

  taskCard: {
    background: 'rgba(255, 255, 255, 0.05)',
    borderRadius: 'var(--zalt-radius, 0.5rem)',
    padding: '20px',
    marginBottom: '16px',
  } as React.CSSProperties,

  taskTitle: {
    fontSize: '16px',
    fontWeight: 600,
    marginBottom: '8px',
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
  } as React.CSSProperties,

  taskDescription: {
    fontSize: '14px',
    color: 'rgba(255, 255, 255, 0.7)',
    marginBottom: '16px',
  } as React.CSSProperties,

  form: {
    display: 'flex',
    flexDirection: 'column' as const,
    gap: '16px',
  } as React.CSSProperties,

  formGroup: {
    display: 'flex',
    flexDirection: 'column' as const,
    gap: '6px',
  } as React.CSSProperties,

  label: {
    fontSize: '13px',
    fontWeight: 500,
    color: 'rgba(255, 255, 255, 0.8)',
  } as React.CSSProperties,

  input: {
    padding: '12px 14px',
    background: 'rgba(255, 255, 255, 0.08)',
    border: '1px solid rgba(255, 255, 255, 0.2)',
    borderRadius: 'var(--zalt-radius, 0.5rem)',
    color: 'var(--zalt-text, #fff)',
    fontSize: '14px',
    outline: 'none',
    transition: 'border-color 0.15s, box-shadow 0.15s',
    width: '100%',
    boxSizing: 'border-box' as const,
  } as React.CSSProperties,

  inputFocus: {
    borderColor: 'var(--zalt-primary, #10b981)',
    boxShadow: '0 0 0 3px rgba(16, 185, 129, 0.1)',
  } as React.CSSProperties,

  inputError: {
    borderColor: '#ef4444',
  } as React.CSSProperties,

  error: {
    padding: '12px 14px',
    background: 'rgba(239, 68, 68, 0.1)',
    border: '1px solid rgba(239, 68, 68, 0.3)',
    borderRadius: 'var(--zalt-radius, 0.5rem)',
    color: '#ef4444',
    fontSize: '13px',
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
  } as React.CSSProperties,

  actions: {
    display: 'flex',
    gap: '12px',
    marginTop: '8px',
  } as React.CSSProperties,

  button: {
    flex: 1,
    padding: '12px 20px',
    background: 'var(--zalt-primary, #10b981)',
    color: '#000',
    border: 'none',
    borderRadius: 'var(--zalt-radius, 0.5rem)',
    fontSize: '14px',
    fontWeight: 600,
    cursor: 'pointer',
    transition: 'opacity 0.15s, transform 0.15s',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '8px',
  } as React.CSSProperties,

  buttonDisabled: {
    opacity: 0.5,
    cursor: 'not-allowed',
  } as React.CSSProperties,

  buttonSecondary: {
    background: 'transparent',
    color: 'rgba(255, 255, 255, 0.7)',
    border: '1px solid rgba(255, 255, 255, 0.2)',
  } as React.CSSProperties,

  orgList: {
    display: 'flex',
    flexDirection: 'column' as const,
    gap: '8px',
  } as React.CSSProperties,

  orgItem: {
    padding: '14px 16px',
    background: 'rgba(255, 255, 255, 0.05)',
    border: '1px solid rgba(255, 255, 255, 0.1)',
    borderRadius: 'var(--zalt-radius, 0.5rem)',
    cursor: 'pointer',
    transition: 'all 0.15s',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
  } as React.CSSProperties,

  orgItemSelected: {
    borderColor: 'var(--zalt-primary, #10b981)',
    background: 'rgba(16, 185, 129, 0.1)',
  } as React.CSSProperties,

  orgName: {
    fontWeight: 500,
  } as React.CSSProperties,

  orgRole: {
    fontSize: '12px',
    color: 'rgba(255, 255, 255, 0.5)',
  } as React.CSSProperties,

  mfaOptions: {
    display: 'flex',
    gap: '12px',
    marginBottom: '16px',
  } as React.CSSProperties,

  mfaOption: {
    flex: 1,
    padding: '16px',
    background: 'rgba(255, 255, 255, 0.05)',
    border: '1px solid rgba(255, 255, 255, 0.1)',
    borderRadius: 'var(--zalt-radius, 0.5rem)',
    cursor: 'pointer',
    textAlign: 'center' as const,
    transition: 'all 0.15s',
  } as React.CSSProperties,

  mfaOptionSelected: {
    borderColor: 'var(--zalt-primary, #10b981)',
    background: 'rgba(16, 185, 129, 0.1)',
  } as React.CSSProperties,

  termsBox: {
    padding: '16px',
    background: 'rgba(255, 255, 255, 0.05)',
    borderRadius: 'var(--zalt-radius, 0.5rem)',
    maxHeight: '200px',
    overflowY: 'auto' as const,
    marginBottom: '16px',
    fontSize: '13px',
    lineHeight: 1.6,
  } as React.CSSProperties,

  checkbox: {
    display: 'flex',
    alignItems: 'center',
    gap: '10px',
    cursor: 'pointer',
  } as React.CSSProperties,

  checkboxInput: {
    width: '18px',
    height: '18px',
    accentColor: 'var(--zalt-primary, #10b981)',
  } as React.CSSProperties,

  spinner: {
    animation: 'zalt-spin 1s linear infinite',
  } as React.CSSProperties,

  loadingContainer: {
    display: 'flex',
    flexDirection: 'column' as const,
    alignItems: 'center',
    justifyContent: 'center',
    padding: '40px',
    gap: '16px',
  } as React.CSSProperties,

  noTasksContainer: {
    textAlign: 'center' as const,
    padding: '40px',
    color: 'rgba(255, 255, 255, 0.6)',
  } as React.CSSProperties,

  blockingBadge: {
    fontSize: '10px',
    padding: '2px 6px',
    background: 'rgba(239, 68, 68, 0.2)',
    color: '#ef4444',
    borderRadius: '4px',
    textTransform: 'uppercase' as const,
    fontWeight: 600,
  } as React.CSSProperties,
};

// ============================================================================
// Helper Components
// ============================================================================

function ErrorIcon(): JSX.Element {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
      <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z" />
    </svg>
  );
}

function LoadingSpinner(): JSX.Element {
  return (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" style={styles.spinner}>
      <style>{`@keyframes zalt-spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }`}</style>
      <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeDasharray="50" strokeDashoffset="15" />
    </svg>
  );
}

function LockIcon(): JSX.Element {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
      <path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z" />
    </svg>
  );
}

function KeyIcon(): JSX.Element {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
      <path d="M12.65 10C11.83 7.67 9.61 6 7 6c-3.31 0-6 2.69-6 6s2.69 6 6 6c2.61 0 4.83-1.67 5.65-4H17v4h4v-4h2v-4H12.65zM7 14c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2z" />
    </svg>
  );
}

function BusinessIcon(): JSX.Element {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
      <path d="M12 7V3H2v18h20V7H12zM6 19H4v-2h2v2zm0-4H4v-2h2v2zm0-4H4V9h2v2zm0-4H4V5h2v2zm4 12H8v-2h2v2zm0-4H8v-2h2v2zm0-4H8V9h2v2zm0-4H8V5h2v2zm10 12h-8v-2h2v-2h-2v-2h2v-2h-2V9h8v10zm-2-8h-2v2h2v-2zm0 4h-2v2h2v-2z" />
    </svg>
  );
}

function EmailIcon(): JSX.Element {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
      <path d="M20 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zm0 4l-8 5-8-5V6l8 5 8-5v2z" />
    </svg>
  );
}

function DocumentIcon(): JSX.Element {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
      <path d="M14 2H6c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.89 2 1.99 2H18c1.1 0 2-.9 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z" />
    </svg>
  );
}

function CheckIcon(): JSX.Element {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
      <path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z" />
    </svg>
  );
}

function getTaskIcon(type: SessionTaskType): JSX.Element {
  switch (type) {
    case 'reset_password':
      return <LockIcon />;
    case 'setup_mfa':
      return <KeyIcon />;
    case 'choose_organization':
      return <BusinessIcon />;
    case 'verify_email':
      return <EmailIcon />;
    case 'accept_terms':
      return <DocumentIcon />;
    default:
      return <DocumentIcon />;
  }
}

function getTaskTitle(type: SessionTaskType, labels?: SessionTaskHandlerProps['labels']): string {
  switch (type) {
    case 'reset_password':
      return labels?.resetPassword || 'Reset Your Password';
    case 'setup_mfa':
      return labels?.setupMfa || 'Set Up Two-Factor Authentication';
    case 'choose_organization':
      return labels?.chooseOrganization || 'Select Organization';
    case 'verify_email':
      return labels?.verifyEmail || 'Verify Your Email';
    case 'accept_terms':
      return labels?.acceptTerms || 'Accept Terms of Service';
    default:
      return 'Complete Required Action';
  }
}

// ============================================================================
// Task Form Components
// ============================================================================

interface PasswordResetFormProps {
  task: SessionTask;
  onComplete: (data: TaskCompletionData) => Promise<boolean>;
  isLoading: boolean;
  error: string | null;
  validatePassword?: (password: string) => { valid: boolean; errors?: string[] };
  labels?: SessionTaskHandlerProps['labels'];
}

function PasswordResetForm({ task, onComplete, isLoading, error, validatePassword, labels }: PasswordResetFormProps): JSX.Element {
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [localError, setLocalError] = useState<string | null>(null);
  const [inputFocused, setInputFocused] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  const handleSubmit = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    setLocalError(null);

    if (!password) {
      setLocalError('Password is required');
      return;
    }

    if (password !== confirmPassword) {
      setLocalError('Passwords do not match');
      return;
    }

    if (validatePassword) {
      const validation = validatePassword(password);
      if (!validation.valid) {
        setLocalError(validation.errors?.join(', ') || 'Password does not meet requirements');
        return;
      }
    }

    await onComplete({ new_password: password });
  }, [password, confirmPassword, validatePassword, onComplete]);

  const displayError = localError || error;
  const reason = task.metadata?.reason;

  return (
    <form onSubmit={handleSubmit} style={styles.form} data-testid="password-reset-form">
      {reason === 'compromised' && (
        <div style={{ ...styles.error, background: 'rgba(239, 68, 68, 0.15)' }}>
          <ErrorIcon />
          <span>Your password was found in a data breach. Please create a new secure password.</span>
        </div>
      )}
      
      <div style={styles.formGroup}>
        <label htmlFor="new-password" style={styles.label}>New Password</label>
        <input
          ref={inputRef}
          id="new-password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          onFocus={() => setInputFocused('password')}
          onBlur={() => setInputFocused(null)}
          placeholder="Enter new password"
          style={{
            ...styles.input,
            ...(inputFocused === 'password' ? styles.inputFocus : {}),
            ...(displayError ? styles.inputError : {}),
          }}
          disabled={isLoading}
          autoComplete="new-password"
          aria-label="New password"
        />
      </div>

      <div style={styles.formGroup}>
        <label htmlFor="confirm-password" style={styles.label}>Confirm Password</label>
        <input
          id="confirm-password"
          type="password"
          value={confirmPassword}
          onChange={(e) => setConfirmPassword(e.target.value)}
          onFocus={() => setInputFocused('confirm')}
          onBlur={() => setInputFocused(null)}
          placeholder="Confirm new password"
          style={{
            ...styles.input,
            ...(inputFocused === 'confirm' ? styles.inputFocus : {}),
          }}
          disabled={isLoading}
          autoComplete="new-password"
          aria-label="Confirm password"
        />
      </div>

      {displayError && (
        <div style={styles.error} role="alert">
          <ErrorIcon />
          <span>{displayError}</span>
        </div>
      )}

      <button
        type="submit"
        style={{
          ...styles.button,
          ...(isLoading || !password || !confirmPassword ? styles.buttonDisabled : {}),
        }}
        disabled={isLoading || !password || !confirmPassword}
      >
        {isLoading ? <LoadingSpinner /> : null}
        {isLoading ? 'Updating...' : (labels?.submit || 'Update Password')}
      </button>
    </form>
  );
}

interface MfaSetupFormProps {
  task: SessionTask;
  onComplete: (data: TaskCompletionData) => Promise<boolean>;
  isLoading: boolean;
  error: string | null;
  availableMethods?: ('totp' | 'webauthn')[];
  labels?: SessionTaskHandlerProps['labels'];
}

function MfaSetupForm({ task, onComplete, isLoading, error, availableMethods = ['totp', 'webauthn'], labels }: MfaSetupFormProps): JSX.Element {
  const [selectedMethod, setSelectedMethod] = useState<'totp' | 'webauthn'>(availableMethods[0] || 'totp');
  const [code, setCode] = useState('');
  const [inputFocused, setInputFocused] = useState(false);

  const handleSubmit = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (selectedMethod === 'totp' && code.length !== 6) {
      return;
    }

    await onComplete({
      mfa_method: selectedMethod,
      verification_code: code,
    });
  }, [selectedMethod, code, onComplete]);

  const handleCodeChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value.replace(/\D/g, '').slice(0, 6);
    setCode(value);
  }, []);

  return (
    <form onSubmit={handleSubmit} style={styles.form} data-testid="mfa-setup-form">
      <p style={styles.taskDescription}>
        {task.metadata?.message || 'Your organization requires two-factor authentication for added security.'}
      </p>

      {availableMethods.length > 1 && (
        <div style={styles.mfaOptions}>
          {availableMethods.includes('totp') && (
            <button
              type="button"
              onClick={() => setSelectedMethod('totp')}
              style={{
                ...styles.mfaOption,
                ...(selectedMethod === 'totp' ? styles.mfaOptionSelected : {}),
              }}
              aria-pressed={selectedMethod === 'totp'}
            >
              <KeyIcon />
              <div style={{ marginTop: '8px', fontWeight: 500 }}>Authenticator App</div>
              <div style={{ fontSize: '12px', color: 'rgba(255,255,255,0.5)', marginTop: '4px' }}>
                Google Authenticator, Authy
              </div>
            </button>
          )}
          {availableMethods.includes('webauthn') && (
            <button
              type="button"
              onClick={() => setSelectedMethod('webauthn')}
              style={{
                ...styles.mfaOption,
                ...(selectedMethod === 'webauthn' ? styles.mfaOptionSelected : {}),
              }}
              aria-pressed={selectedMethod === 'webauthn'}
            >
              <LockIcon />
              <div style={{ marginTop: '8px', fontWeight: 500 }}>Passkey</div>
              <div style={{ fontSize: '12px', color: 'rgba(255,255,255,0.5)', marginTop: '4px' }}>
                Most secure option
              </div>
            </button>
          )}
        </div>
      )}

      {selectedMethod === 'totp' && (
        <div style={styles.formGroup}>
          <label htmlFor="mfa-code" style={styles.label}>
            Enter the 6-digit code from your authenticator app
          </label>
          <input
            id="mfa-code"
            type="text"
            inputMode="numeric"
            pattern="[0-9]*"
            value={code}
            onChange={handleCodeChange}
            onFocus={() => setInputFocused(true)}
            onBlur={() => setInputFocused(false)}
            placeholder="000000"
            style={{
              ...styles.input,
              ...(inputFocused ? styles.inputFocus : {}),
              ...(error ? styles.inputError : {}),
              letterSpacing: '0.5em',
              textAlign: 'center',
              fontSize: '18px',
              fontFamily: 'monospace',
            }}
            disabled={isLoading}
            autoComplete="one-time-code"
            aria-label="MFA code"
          />
        </div>
      )}

      {selectedMethod === 'webauthn' && (
        <p style={{ ...styles.taskDescription, textAlign: 'center' }}>
          Click the button below to register your passkey or security key.
        </p>
      )}

      {error && (
        <div style={styles.error} role="alert">
          <ErrorIcon />
          <span>{error}</span>
        </div>
      )}

      <button
        type="submit"
        style={{
          ...styles.button,
          ...(isLoading || (selectedMethod === 'totp' && code.length !== 6) ? styles.buttonDisabled : {}),
        }}
        disabled={isLoading || (selectedMethod === 'totp' && code.length !== 6)}
      >
        {isLoading ? <LoadingSpinner /> : null}
        {isLoading ? 'Setting up...' : (selectedMethod === 'webauthn' ? 'Register Passkey' : 'Verify & Enable')}
      </button>
    </form>
  );
}

interface OrganizationSelectorProps {
  task: SessionTask;
  onComplete: (data: TaskCompletionData) => Promise<boolean>;
  isLoading: boolean;
  error: string | null;
  labels?: SessionTaskHandlerProps['labels'];
}

function OrganizationSelector({ task, onComplete, isLoading, error, labels }: OrganizationSelectorProps): JSX.Element {
  const [selectedOrg, setSelectedOrg] = useState<string | null>(null);
  const organizations = task.metadata?.available_organizations || [];

  const handleSubmit = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedOrg) return;
    await onComplete({ organization_id: selectedOrg });
  }, [selectedOrg, onComplete]);

  return (
    <form onSubmit={handleSubmit} style={styles.form} data-testid="organization-selector-form">
      <p style={styles.taskDescription}>
        {task.metadata?.message || 'You belong to multiple organizations. Please select one to continue.'}
      </p>

      <div style={styles.orgList} role="listbox" aria-label="Organizations">
        {organizations.map((org: OrganizationOption) => (
          <div
            key={org.id}
            onClick={() => setSelectedOrg(org.id)}
            onKeyDown={(e) => e.key === 'Enter' && setSelectedOrg(org.id)}
            style={{
              ...styles.orgItem,
              ...(selectedOrg === org.id ? styles.orgItemSelected : {}),
            }}
            role="option"
            aria-selected={selectedOrg === org.id}
            tabIndex={0}
          >
            <div>
              <div style={styles.orgName}>{org.name}</div>
              {org.role && <div style={styles.orgRole}>{org.role}</div>}
            </div>
            {selectedOrg === org.id && <CheckIcon />}
          </div>
        ))}
      </div>

      {error && (
        <div style={styles.error} role="alert">
          <ErrorIcon />
          <span>{error}</span>
        </div>
      )}

      <button
        type="submit"
        style={{
          ...styles.button,
          ...(isLoading || !selectedOrg ? styles.buttonDisabled : {}),
        }}
        disabled={isLoading || !selectedOrg}
      >
        {isLoading ? <LoadingSpinner /> : null}
        {isLoading ? 'Selecting...' : (labels?.submit || 'Continue')}
      </button>
    </form>
  );
}

interface EmailVerificationFormProps {
  task: SessionTask;
  onComplete: (data: TaskCompletionData) => Promise<boolean>;
  isLoading: boolean;
  error: string | null;
  labels?: SessionTaskHandlerProps['labels'];
}

function EmailVerificationForm({ task, onComplete, isLoading, error, labels }: EmailVerificationFormProps): JSX.Element {
  const [code, setCode] = useState('');
  const [inputFocused, setInputFocused] = useState(false);

  const handleSubmit = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    if (code.length !== 6) return;
    await onComplete({ verification_code: code });
  }, [code, onComplete]);

  const handleCodeChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value.replace(/\D/g, '').slice(0, 6);
    setCode(value);
  }, []);

  const email = task.metadata?.email || 'your email';

  return (
    <form onSubmit={handleSubmit} style={styles.form} data-testid="email-verification-form">
      <p style={styles.taskDescription}>
        We've sent a verification code to <strong>{email}</strong>. Please enter it below.
      </p>

      <div style={styles.formGroup}>
        <label htmlFor="email-code" style={styles.label}>Verification Code</label>
        <input
          id="email-code"
          type="text"
          inputMode="numeric"
          pattern="[0-9]*"
          value={code}
          onChange={handleCodeChange}
          onFocus={() => setInputFocused(true)}
          onBlur={() => setInputFocused(false)}
          placeholder="000000"
          style={{
            ...styles.input,
            ...(inputFocused ? styles.inputFocus : {}),
            ...(error ? styles.inputError : {}),
            letterSpacing: '0.5em',
            textAlign: 'center',
            fontSize: '18px',
            fontFamily: 'monospace',
          }}
          disabled={isLoading}
          autoComplete="one-time-code"
          aria-label="Email verification code"
        />
      </div>

      {error && (
        <div style={styles.error} role="alert">
          <ErrorIcon />
          <span>{error}</span>
        </div>
      )}

      <button
        type="submit"
        style={{
          ...styles.button,
          ...(isLoading || code.length !== 6 ? styles.buttonDisabled : {}),
        }}
        disabled={isLoading || code.length !== 6}
      >
        {isLoading ? <LoadingSpinner /> : null}
        {isLoading ? 'Verifying...' : (labels?.submit || 'Verify Email')}
      </button>
    </form>
  );
}

interface TermsAcceptanceFormProps {
  task: SessionTask;
  onComplete: (data: TaskCompletionData) => Promise<boolean>;
  isLoading: boolean;
  error: string | null;
  labels?: SessionTaskHandlerProps['labels'];
}

function TermsAcceptanceForm({ task, onComplete, isLoading, error, labels }: TermsAcceptanceFormProps): JSX.Element {
  const [accepted, setAccepted] = useState(false);

  const handleSubmit = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    if (!accepted) return;
    await onComplete({
      accepted: true,
      terms_version: task.metadata?.terms_version,
    });
  }, [accepted, task.metadata?.terms_version, onComplete]);

  const termsUrl = task.metadata?.terms_url;

  return (
    <form onSubmit={handleSubmit} style={styles.form} data-testid="terms-acceptance-form">
      <p style={styles.taskDescription}>
        {task.metadata?.message || 'Please review and accept our updated terms of service to continue.'}
      </p>

      {termsUrl && (
        <div style={styles.termsBox}>
          <a 
            href={termsUrl} 
            target="_blank" 
            rel="noopener noreferrer"
            style={{ color: 'var(--zalt-primary, #10b981)' }}
          >
            View Terms of Service →
          </a>
        </div>
      )}

      <label style={styles.checkbox}>
        <input
          type="checkbox"
          checked={accepted}
          onChange={(e) => setAccepted(e.target.checked)}
          style={styles.checkboxInput}
          disabled={isLoading}
          aria-label="Accept terms of service"
        />
        <span>I have read and agree to the Terms of Service</span>
      </label>

      {error && (
        <div style={styles.error} role="alert">
          <ErrorIcon />
          <span>{error}</span>
        </div>
      )}

      <button
        type="submit"
        style={{
          ...styles.button,
          ...(isLoading || !accepted ? styles.buttonDisabled : {}),
        }}
        disabled={isLoading || !accepted}
      >
        {isLoading ? <LoadingSpinner /> : null}
        {isLoading ? 'Accepting...' : (labels?.submit || 'Accept & Continue')}
      </button>
    </form>
  );
}

// ============================================================================
// Main Component
// ============================================================================

/**
 * SessionTaskHandler - Component for handling post-login session tasks
 * 
 * @example
 * ```tsx
 * import { SessionTaskHandler } from '@zalt/react';
 * 
 * function App() {
 *   return (
 *     <SessionTaskHandler
 *       accessToken={accessToken}
 *       onAllTasksCompleted={() => router.push('/dashboard')}
 *       onError={(error) => console.error(error)}
 *     />
 *   );
 * }
 * ```
 */
export function SessionTaskHandler({
  apiUrl,
  accessToken,
  autoFetch = true,
  pollingInterval = 0,
  onTaskCompleted,
  onAllTasksCompleted,
  onError,
  className = '',
  title = 'Complete Required Actions',
  subtitle = 'Please complete the following to continue',
  showProgress = true,
  allowSkip = true,
  labels,
  customRenderers,
  renderNoTasks,
  renderLoading,
  validatePassword,
  availableMfaMethods = ['totp', 'webauthn'],
  redirectUrl,
}: SessionTaskHandlerProps): JSX.Element {
  const {
    tasks,
    currentTask,
    hasBlockingTasks,
    pendingTaskCount,
    isLoading,
    isCompleting,
    error,
    completeTask,
    skipTask,
    clearError,
  } = useSessionTasks({
    apiUrl,
    accessToken,
    autoFetch,
    pollingInterval,
    onTaskCompleted,
    onAllTasksCompleted: () => {
      onAllTasksCompleted?.();
      if (redirectUrl && typeof window !== 'undefined') {
        window.location.href = redirectUrl;
      }
    },
    onError,
  });

  // Handle task completion
  const handleComplete = useCallback(async (data?: TaskCompletionData): Promise<boolean> => {
    if (!currentTask) return false;
    clearError();
    return completeTask(currentTask.id, data);
  }, [currentTask, completeTask, clearError]);

  // Handle task skip
  const handleSkip = useCallback(async (): Promise<boolean> => {
    if (!currentTask || currentTask.blocking) return false;
    return skipTask(currentTask.id);
  }, [currentTask, skipTask]);

  // Render loading state
  if (isLoading && tasks.length === 0) {
    if (renderLoading) {
      return <>{renderLoading()}</>;
    }
    return (
      <div style={styles.container} className={`zalt-session-task-handler ${className}`} data-testid="session-task-handler">
        <div style={styles.loadingContainer}>
          <LoadingSpinner />
          <span>{labels?.loading || 'Loading tasks...'}</span>
        </div>
      </div>
    );
  }

  // Render no tasks state
  if (!currentTask) {
    if (renderNoTasks) {
      return <>{renderNoTasks()}</>;
    }
    return (
      <div style={styles.container} className={`zalt-session-task-handler ${className}`} data-testid="session-task-handler">
        <div style={styles.noTasksContainer}>
          <CheckIcon />
          <p>All tasks completed!</p>
        </div>
      </div>
    );
  }

  // Render task form based on type
  const renderTaskForm = (): React.ReactNode => {
    const rendererProps: TaskRendererProps = {
      task: currentTask,
      onComplete: handleComplete,
      onSkip: !currentTask.blocking && allowSkip ? handleSkip : undefined,
      isLoading: isCompleting,
      error,
    };

    // Check for custom renderer
    const customRenderer = customRenderers?.[currentTask.type];
    if (customRenderer) {
      return customRenderer(rendererProps);
    }

    // Default renderers
    switch (currentTask.type) {
      case 'reset_password':
        return (
          <PasswordResetForm
            task={currentTask}
            onComplete={handleComplete}
            isLoading={isCompleting}
            error={error}
            validatePassword={validatePassword}
            labels={labels}
          />
        );
      case 'setup_mfa':
        return (
          <MfaSetupForm
            task={currentTask}
            onComplete={handleComplete}
            isLoading={isCompleting}
            error={error}
            availableMethods={availableMfaMethods}
            labels={labels}
          />
        );
      case 'choose_organization':
        return (
          <OrganizationSelector
            task={currentTask}
            onComplete={handleComplete}
            isLoading={isCompleting}
            error={error}
            labels={labels}
          />
        );
      case 'verify_email':
        return (
          <EmailVerificationForm
            task={currentTask}
            onComplete={handleComplete}
            isLoading={isCompleting}
            error={error}
            labels={labels}
          />
        );
      case 'accept_terms':
        return (
          <TermsAcceptanceForm
            task={currentTask}
            onComplete={handleComplete}
            isLoading={isCompleting}
            error={error}
            labels={labels}
          />
        );
      default:
        return (
          <div style={styles.taskDescription}>
            {currentTask.metadata?.message || 'Please complete this task to continue.'}
            <button
              onClick={() => handleComplete()}
              style={styles.button}
              disabled={isCompleting}
            >
              {isCompleting ? <LoadingSpinner /> : 'Complete'}
            </button>
          </div>
        );
    }
  };

  return (
    <div 
      style={styles.container} 
      className={`zalt-session-task-handler ${className}`}
      data-testid="session-task-handler"
      role="main"
      aria-label="Session task handler"
    >
      {/* Header */}
      <div style={styles.header}>
        <h1 style={styles.title}>{title}</h1>
        <p style={styles.subtitle}>{subtitle}</p>
      </div>

      {/* Progress indicator */}
      {showProgress && pendingTaskCount > 1 && (
        <div style={styles.progress} role="progressbar" aria-valuenow={1} aria-valuemax={pendingTaskCount}>
          {tasks.map((task, index) => (
            <div
              key={task.id}
              style={{
                ...styles.progressDot,
                ...(task.id === currentTask.id ? styles.progressDotActive : {}),
                ...(task.status === 'completed' ? styles.progressDotCompleted : {}),
              }}
              aria-label={`Task ${index + 1} of ${pendingTaskCount}`}
            />
          ))}
        </div>
      )}

      {/* Task card */}
      <div style={styles.taskCard}>
        <div style={styles.taskTitle}>
          {getTaskIcon(currentTask.type)}
          <span>{getTaskTitle(currentTask.type, labels)}</span>
          {currentTask.blocking && (
            <span style={styles.blockingBadge}>Required</span>
          )}
        </div>

        {/* Task form */}
        {renderTaskForm()}

        {/* Skip button for non-blocking tasks */}
        {!currentTask.blocking && allowSkip && (
          <div style={{ ...styles.actions, marginTop: '16px' }}>
            <button
              onClick={handleSkip}
              style={{ ...styles.button, ...styles.buttonSecondary }}
              disabled={isCompleting}
              type="button"
            >
              {labels?.skip || 'Skip for now'}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

export default SessionTaskHandler;

// Re-export types
export type {
  SessionTask,
  SessionTaskType,
  SessionTaskStatus,
  TaskCompletionData,
  OrganizationOption,
  SessionTaskMetadata,
} from '../hooks/useSessionTasks';
