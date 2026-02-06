/**
 * ReverificationModal Component
 * @zalt/react
 * 
 * Modal component for step-up authentication (reverification).
 * Supports password, MFA (TOTP), and WebAuthn verification methods.
 * Auto-retries original request after successful verification.
 * 
 * Validates: Requirement 3.6 (Reverification UI Component)
 */

'use client';

import React, { useState, useCallback, useEffect, useRef } from 'react';
import { useReverification, type ReverificationLevel } from '../hooks/useReverification';

// ============================================================================
// Types
// ============================================================================

/**
 * ReverificationModal component props
 */
export interface ReverificationModalProps {
  /** Whether the modal is open */
  isOpen?: boolean;
  /** Required reverification level */
  requiredLevel?: ReverificationLevel | null;
  /** Validity period in minutes */
  validityMinutes?: number | null;
  /** Loading state */
  isLoading?: boolean;
  /** Error message */
  error?: string | null;
  /** Callback when password is submitted */
  onPasswordSubmit?: (password: string) => Promise<void>;
  /** Callback when MFA code is submitted */
  onMFASubmit?: (code: string) => Promise<void>;
  /** Callback when WebAuthn is initiated */
  onWebAuthnSubmit?: () => Promise<void>;
  /** Callback when modal is closed */
  onClose?: () => void;
  /** Custom class name */
  className?: string;
  /** Custom title */
  title?: string;
  /** Custom subtitle */
  subtitle?: string;
  /** Show close button */
  showCloseButton?: boolean;
  /** Allow closing by clicking backdrop */
  closeOnBackdropClick?: boolean;
  /** Allow closing by pressing Escape */
  closeOnEscape?: boolean;
  /** Available verification methods (auto-detected from requiredLevel if not provided) */
  availableMethods?: ReverificationLevel[];
  /** Default selected method */
  defaultMethod?: ReverificationLevel;
  /** Custom labels */
  labels?: {
    password?: string;
    mfa?: string;
    webauthn?: string;
    submit?: string;
    cancel?: string;
    switchMethod?: string;
  };
}


// ============================================================================
// Styles
// ============================================================================

const styles = {
  overlay: {
    position: 'fixed' as const,
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    background: 'rgba(0, 0, 0, 0.7)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    zIndex: 9999,
    backdropFilter: 'blur(4px)',
  } as React.CSSProperties,

  modal: {
    background: 'var(--zalt-modal-bg, #1a1a2e)',
    borderRadius: 'var(--zalt-radius, 0.75rem)',
    padding: '24px',
    maxWidth: '400px',
    width: '100%',
    margin: '16px',
    boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.5)',
    border: '1px solid rgba(255, 255, 255, 0.1)',
    fontFamily: 'var(--zalt-font, system-ui, sans-serif)',
    color: 'var(--zalt-text, #fff)',
  } as React.CSSProperties,

  header: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    marginBottom: '20px',
  } as React.CSSProperties,

  titleContainer: {
    flex: 1,
  } as React.CSSProperties,

  title: {
    fontSize: '20px',
    fontWeight: 600,
    margin: 0,
    marginBottom: '4px',
  } as React.CSSProperties,

  subtitle: {
    fontSize: '14px',
    color: 'rgba(255, 255, 255, 0.6)',
    margin: 0,
  } as React.CSSProperties,

  closeButton: {
    background: 'transparent',
    border: 'none',
    color: 'rgba(255, 255, 255, 0.5)',
    cursor: 'pointer',
    padding: '4px',
    marginLeft: '8px',
    borderRadius: '4px',
    transition: 'color 0.15s',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
  } as React.CSSProperties,

  methodTabs: {
    display: 'flex',
    gap: '8px',
    marginBottom: '20px',
    borderBottom: '1px solid rgba(255, 255, 255, 0.1)',
    paddingBottom: '12px',
  } as React.CSSProperties,

  methodTab: {
    padding: '8px 16px',
    background: 'transparent',
    border: '1px solid rgba(255, 255, 255, 0.2)',
    borderRadius: 'var(--zalt-radius, 0.5rem)',
    color: 'rgba(255, 255, 255, 0.7)',
    fontSize: '13px',
    fontWeight: 500,
    cursor: 'pointer',
    transition: 'all 0.15s',
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
  } as React.CSSProperties,

  methodTabActive: {
    background: 'var(--zalt-primary, #10b981)',
    borderColor: 'var(--zalt-primary, #10b981)',
    color: '#000',
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

  webauthnPrompt: {
    textAlign: 'center' as const,
    padding: '24px',
  } as React.CSSProperties,

  webauthnIcon: {
    width: '64px',
    height: '64px',
    margin: '0 auto 16px',
    background: 'rgba(16, 185, 129, 0.1)',
    borderRadius: '50%',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    color: 'var(--zalt-primary, #10b981)',
  } as React.CSSProperties,

  webauthnText: {
    fontSize: '14px',
    color: 'rgba(255, 255, 255, 0.7)',
    marginBottom: '20px',
  } as React.CSSProperties,

  validityInfo: {
    fontSize: '12px',
    color: 'rgba(255, 255, 255, 0.5)',
    textAlign: 'center' as const,
    marginTop: '12px',
  } as React.CSSProperties,

  spinner: {
    animation: 'zalt-spin 1s linear infinite',
  } as React.CSSProperties,
};


// ============================================================================
// Helper Components
// ============================================================================

function CloseIcon(): JSX.Element {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
      <path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z" />
    </svg>
  );
}

function LockIcon(): JSX.Element {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
      <path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z" />
    </svg>
  );
}

function KeyIcon(): JSX.Element {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
      <path d="M12.65 10C11.83 7.67 9.61 6 7 6c-3.31 0-6 2.69-6 6s2.69 6 6 6c2.61 0 4.83-1.67 5.65-4H17v4h4v-4h2v-4H12.65zM7 14c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2z" />
    </svg>
  );
}

function FingerprintIcon(): JSX.Element {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
      <path d="M17.81 4.47c-.08 0-.16-.02-.23-.06C15.66 3.42 14 3 12.01 3c-1.98 0-3.86.47-5.57 1.41-.24.13-.54.04-.68-.2-.13-.24-.04-.55.2-.68C7.82 2.52 9.86 2 12.01 2c2.13 0 3.99.47 6.03 1.52.25.13.34.43.21.67-.09.18-.26.28-.44.28zM3.5 9.72c-.1 0-.2-.03-.29-.09-.23-.16-.28-.47-.12-.7.99-1.4 2.25-2.5 3.75-3.27C9.98 4.04 14 4.03 17.15 5.65c1.5.77 2.76 1.86 3.75 3.25.16.22.11.54-.12.7-.23.16-.54.11-.7-.12-.9-1.26-2.04-2.25-3.39-2.94-2.87-1.47-6.54-1.47-9.4.01-1.36.7-2.5 1.7-3.4 2.96-.08.14-.23.21-.39.21zm6.25 12.07c-.13 0-.26-.05-.35-.15-.87-.87-1.34-1.43-2.01-2.64-.69-1.23-1.05-2.73-1.05-4.34 0-2.97 2.54-5.39 5.66-5.39s5.66 2.42 5.66 5.39c0 .28-.22.5-.5.5s-.5-.22-.5-.5c0-2.42-2.09-4.39-4.66-4.39-2.57 0-4.66 1.97-4.66 4.39 0 1.44.32 2.77.93 3.85.64 1.15 1.08 1.64 1.85 2.42.19.2.19.51 0 .71-.11.1-.24.15-.37.15zm7.17-1.85c-1.19 0-2.24-.3-3.1-.89-1.49-1.01-2.38-2.65-2.38-4.39 0-.28.22-.5.5-.5s.5.22.5.5c0 1.41.72 2.74 1.94 3.56.71.48 1.54.71 2.54.71.24 0 .64-.03 1.04-.1.27-.05.53.13.58.41.05.27-.13.53-.41.58-.57.11-1.07.12-1.21.12zM14.91 22c-.04 0-.09-.01-.13-.02-1.59-.44-2.63-1.03-3.72-2.1-1.4-1.39-2.17-3.24-2.17-5.22 0-1.62 1.38-2.94 3.08-2.94 1.7 0 3.08 1.32 3.08 2.94 0 1.07.93 1.94 2.08 1.94s2.08-.87 2.08-1.94c0-3.77-3.25-6.83-7.25-6.83-2.84 0-5.44 1.58-6.61 4.03-.39.81-.59 1.76-.59 2.8 0 .78.07 2.01.67 3.61.1.26-.03.55-.29.64-.26.1-.55-.04-.64-.29-.49-1.31-.73-2.61-.73-3.96 0-1.2.23-2.29.68-3.24 1.33-2.79 4.28-4.6 7.51-4.6 4.55 0 8.25 3.51 8.25 7.83 0 1.62-1.38 2.94-3.08 2.94s-3.08-1.32-3.08-2.94c0-1.07-.93-1.94-2.08-1.94s-2.08.87-2.08 1.94c0 1.71.66 3.31 1.87 4.51.95.94 1.86 1.46 3.27 1.85.27.07.42.35.35.61-.05.23-.26.38-.47.38z" />
    </svg>
  );
}

function ErrorIcon(): JSX.Element {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
      <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z" />
    </svg>
  );
}

function LoadingSpinner(): JSX.Element {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" style={styles.spinner}>
      <style>{`@keyframes zalt-spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }`}</style>
      <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeDasharray="50" strokeDashoffset="15" />
    </svg>
  );
}

function getMethodLabel(method: ReverificationLevel, labels?: ReverificationModalProps['labels']): string {
  switch (method) {
    case 'password':
      return labels?.password || 'Password';
    case 'mfa':
      return labels?.mfa || 'Authenticator';
    case 'webauthn':
      return labels?.webauthn || 'Passkey';
    default:
      return method;
  }
}

function getMethodIcon(method: ReverificationLevel): JSX.Element {
  switch (method) {
    case 'password':
      return <LockIcon />;
    case 'mfa':
      return <KeyIcon />;
    case 'webauthn':
      return <FingerprintIcon />;
    default:
      return <LockIcon />;
  }
}

function getAvailableMethods(requiredLevel: ReverificationLevel | null | undefined): ReverificationLevel[] {
  // Higher levels can satisfy lower level requirements
  // webauthn > mfa > password
  switch (requiredLevel) {
    case 'webauthn':
      return ['webauthn'];
    case 'mfa':
      return ['mfa', 'webauthn'];
    case 'password':
    default:
      return ['password', 'mfa', 'webauthn'];
  }
}


// ============================================================================
// Form Components
// ============================================================================

interface PasswordFormProps {
  onSubmit: (password: string) => Promise<void>;
  isLoading: boolean;
  error: string | null;
  labels?: ReverificationModalProps['labels'];
}

function PasswordForm({ onSubmit, isLoading, error, labels }: PasswordFormProps): JSX.Element {
  const [password, setPassword] = useState('');
  const [inputFocused, setInputFocused] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  const handleSubmit = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    if (!password.trim() || isLoading) return;
    await onSubmit(password);
  }, [password, isLoading, onSubmit]);

  return (
    <form onSubmit={handleSubmit} style={styles.form} data-testid="password-form">
      <div style={styles.formGroup}>
        <label htmlFor="reverify-password" style={styles.label}>
          Enter your password to continue
        </label>
        <input
          ref={inputRef}
          id="reverify-password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          onFocus={() => setInputFocused(true)}
          onBlur={() => setInputFocused(false)}
          placeholder="••••••••"
          style={{
            ...styles.input,
            ...(inputFocused ? styles.inputFocus : {}),
            ...(error ? styles.inputError : {}),
          }}
          disabled={isLoading}
          autoComplete="current-password"
          aria-label="Password"
          aria-describedby={error ? 'password-error' : undefined}
        />
      </div>
      {error && (
        <div style={styles.error} id="password-error" role="alert">
          <ErrorIcon />
          <span>{error}</span>
        </div>
      )}
      <button
        type="submit"
        style={{
          ...styles.button,
          ...(isLoading || !password.trim() ? styles.buttonDisabled : {}),
        }}
        disabled={isLoading || !password.trim()}
        aria-label={labels?.submit || 'Verify'}
      >
        {isLoading ? <LoadingSpinner /> : null}
        {isLoading ? 'Verifying...' : (labels?.submit || 'Verify')}
      </button>
    </form>
  );
}

interface MFAFormProps {
  onSubmit: (code: string) => Promise<void>;
  isLoading: boolean;
  error: string | null;
  labels?: ReverificationModalProps['labels'];
}

function MFAForm({ onSubmit, isLoading, error, labels }: MFAFormProps): JSX.Element {
  const [code, setCode] = useState('');
  const [inputFocused, setInputFocused] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  const handleSubmit = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    if (!code.trim() || isLoading) return;
    await onSubmit(code);
  }, [code, isLoading, onSubmit]);

  const handleCodeChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    // Only allow digits and limit to 6 characters for TOTP
    const value = e.target.value.replace(/\D/g, '').slice(0, 6);
    setCode(value);
  }, []);

  return (
    <form onSubmit={handleSubmit} style={styles.form} data-testid="mfa-form">
      <div style={styles.formGroup}>
        <label htmlFor="reverify-mfa" style={styles.label}>
          Enter the 6-digit code from your authenticator app
        </label>
        <input
          ref={inputRef}
          id="reverify-mfa"
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
          aria-describedby={error ? 'mfa-error' : undefined}
        />
      </div>
      {error && (
        <div style={styles.error} id="mfa-error" role="alert">
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
        aria-label={labels?.submit || 'Verify'}
      >
        {isLoading ? <LoadingSpinner /> : null}
        {isLoading ? 'Verifying...' : (labels?.submit || 'Verify')}
      </button>
    </form>
  );
}

interface WebAuthnFormProps {
  onSubmit: () => Promise<void>;
  isLoading: boolean;
  error: string | null;
  labels?: ReverificationModalProps['labels'];
}

function WebAuthnForm({ onSubmit, isLoading, error, labels }: WebAuthnFormProps): JSX.Element {
  const handleSubmit = useCallback(async () => {
    if (isLoading) return;
    await onSubmit();
  }, [isLoading, onSubmit]);

  return (
    <div style={styles.webauthnPrompt} data-testid="webauthn-form">
      <div style={styles.webauthnIcon}>
        <FingerprintIcon />
      </div>
      <p style={styles.webauthnText}>
        Use your passkey or security key to verify your identity.
        This is the most secure verification method.
      </p>
      {error && (
        <div style={{ ...styles.error, marginBottom: '16px' }} role="alert">
          <ErrorIcon />
          <span>{error}</span>
        </div>
      )}
      <button
        type="button"
        onClick={handleSubmit}
        style={{
          ...styles.button,
          ...(isLoading ? styles.buttonDisabled : {}),
          width: '100%',
        }}
        disabled={isLoading}
        aria-label={labels?.submit || 'Use Passkey'}
      >
        {isLoading ? <LoadingSpinner /> : <FingerprintIcon />}
        {isLoading ? 'Waiting for passkey...' : (labels?.submit || 'Use Passkey')}
      </button>
    </div>
  );
}


// ============================================================================
// Main Component
// ============================================================================

/**
 * ReverificationModal - Modal for step-up authentication
 * 
 * @example
 * ```tsx
 * import { useReverification, ReverificationModal } from '@zalt/react';
 * 
 * function SensitiveAction() {
 *   const {
 *     isModalOpen,
 *     requiredLevel,
 *     validityMinutes,
 *     verifyWithPassword,
 *     verifyWithMFA,
 *     verifyWithWebAuthn,
 *     getWebAuthnChallenge,
 *     closeModal,
 *     isLoading,
 *     error,
 *   } = useReverification();
 * 
 *   return (
 *     <ReverificationModal
 *       isOpen={isModalOpen}
 *       requiredLevel={requiredLevel}
 *       validityMinutes={validityMinutes}
 *       isLoading={isLoading}
 *       error={error}
 *       onPasswordSubmit={verifyWithPassword}
 *       onMFASubmit={verifyWithMFA}
 *       onWebAuthnSubmit={async () => {
 *         const { challenge } = await getWebAuthnChallenge();
 *         const credential = await navigator.credentials.get({ ... });
 *         await verifyWithWebAuthn(credential, challenge);
 *       }}
 *       onClose={closeModal}
 *     />
 *   );
 * }
 * ```
 */
export function ReverificationModal({
  isOpen = false,
  requiredLevel = 'password',
  validityMinutes = 10,
  isLoading = false,
  error = null,
  onPasswordSubmit,
  onMFASubmit,
  onWebAuthnSubmit,
  onClose,
  className = '',
  title = 'Verify Your Identity',
  subtitle = 'This action requires additional verification for security.',
  showCloseButton = true,
  closeOnBackdropClick = true,
  closeOnEscape = true,
  availableMethods,
  defaultMethod,
  labels,
}: ReverificationModalProps): JSX.Element | null {
  // Determine available methods
  const methods = availableMethods || getAvailableMethods(requiredLevel);
  
  // State for selected method
  const [selectedMethod, setSelectedMethod] = useState<ReverificationLevel>(
    defaultMethod || methods[0] || 'password'
  );
  
  // Ref for focus trap
  const modalRef = useRef<HTMLDivElement>(null);
  const previousActiveElement = useRef<Element | null>(null);

  // Handle escape key
  useEffect(() => {
    if (!isOpen || !closeOnEscape) return;

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && onClose) {
        onClose();
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, closeOnEscape, onClose]);

  // Focus trap and restore focus
  useEffect(() => {
    if (isOpen) {
      previousActiveElement.current = document.activeElement;
      modalRef.current?.focus();
    } else if (previousActiveElement.current instanceof HTMLElement) {
      previousActiveElement.current.focus();
    }
  }, [isOpen]);

  // Handle backdrop click
  const handleBackdropClick = useCallback((e: React.MouseEvent) => {
    if (closeOnBackdropClick && e.target === e.currentTarget && onClose) {
      onClose();
    }
  }, [closeOnBackdropClick, onClose]);

  // Reset selected method when modal opens
  useEffect(() => {
    if (isOpen) {
      setSelectedMethod(defaultMethod || methods[0] || 'password');
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isOpen, defaultMethod]);

  // Don't render if not open
  if (!isOpen) {
    return null;
  }

  return (
    <div
      style={styles.overlay}
      onClick={handleBackdropClick}
      role="dialog"
      aria-modal="true"
      aria-labelledby="reverification-title"
      aria-describedby="reverification-subtitle"
      data-testid="reverification-modal"
      className={`zalt-reverification-modal ${className}`}
    >
      <div
        ref={modalRef}
        style={styles.modal}
        tabIndex={-1}
        role="document"
      >
        {/* Header */}
        <div style={styles.header}>
          <div style={styles.titleContainer}>
            <h2 id="reverification-title" style={styles.title}>{title}</h2>
            <p id="reverification-subtitle" style={styles.subtitle}>{subtitle}</p>
          </div>
          {showCloseButton && onClose && (
            <button
              onClick={onClose}
              style={styles.closeButton}
              aria-label="Close"
              type="button"
            >
              <CloseIcon />
            </button>
          )}
        </div>

        {/* Method Tabs (only show if multiple methods available) */}
        {methods.length > 1 && (
          <div style={styles.methodTabs} role="tablist" aria-label="Verification methods">
            {methods.map((method) => (
              <button
                key={method}
                onClick={() => setSelectedMethod(method)}
                style={{
                  ...styles.methodTab,
                  ...(selectedMethod === method ? styles.methodTabActive : {}),
                }}
                role="tab"
                aria-selected={selectedMethod === method}
                aria-controls={`${method}-panel`}
                type="button"
              >
                {getMethodIcon(method)}
                {getMethodLabel(method, labels)}
              </button>
            ))}
          </div>
        )}

        {/* Form Content */}
        <div
          id={`${selectedMethod}-panel`}
          role="tabpanel"
          aria-labelledby={`${selectedMethod}-tab`}
        >
          {selectedMethod === 'password' && onPasswordSubmit && (
            <PasswordForm
              onSubmit={onPasswordSubmit}
              isLoading={isLoading}
              error={error}
              labels={labels}
            />
          )}
          {selectedMethod === 'mfa' && onMFASubmit && (
            <MFAForm
              onSubmit={onMFASubmit}
              isLoading={isLoading}
              error={error}
              labels={labels}
            />
          )}
          {selectedMethod === 'webauthn' && onWebAuthnSubmit && (
            <WebAuthnForm
              onSubmit={onWebAuthnSubmit}
              isLoading={isLoading}
              error={error}
              labels={labels}
            />
          )}
        </div>

        {/* Validity Info */}
        {validityMinutes && (
          <p style={styles.validityInfo}>
            Verification will be valid for {validityMinutes} minute{validityMinutes !== 1 ? 's' : ''}
          </p>
        )}

        {/* Cancel Button */}
        {onClose && (
          <div style={{ ...styles.actions, marginTop: '16px' }}>
            <button
              onClick={onClose}
              style={{ ...styles.button, ...styles.buttonSecondary }}
              type="button"
              aria-label={labels?.cancel || 'Cancel'}
            >
              {labels?.cancel || 'Cancel'}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

export default ReverificationModal;
