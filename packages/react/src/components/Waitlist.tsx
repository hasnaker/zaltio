/**
 * Waitlist Component
 * @zalt/react
 * 
 * Component for waitlist signup and position display.
 * Allows users to join a waitlist when registration is restricted.
 * 
 * Validates: Requirement 5.7
 */

'use client';

import React, { useState, useCallback, useEffect } from 'react';

// ============================================================================
// Types
// ============================================================================

/**
 * Waitlist entry status
 */
export type WaitlistStatus = 'pending' | 'approved' | 'rejected' | 'invited';

/**
 * Waitlist entry response
 */
export interface WaitlistEntry {
  id: string;
  email: string;
  position: number;
  status: WaitlistStatus;
  referral_code: string;
  created_at: string;
}

/**
 * Waitlist join result
 */
export interface WaitlistJoinResult {
  entry_id: string;
  position: number;
  referral_code: string;
  message: string;
}

/**
 * Waitlist position result
 */
export interface WaitlistPositionResult {
  entry_id: string;
  position: number;
  total: number;
}

/**
 * Custom metadata for waitlist signup
 */
export interface WaitlistMetadata {
  firstName?: string;
  lastName?: string;
  company?: string;
  useCase?: string;
  source?: string;
}

/**
 * Waitlist component props
 */
export interface WaitlistProps {
  /** Realm ID for the waitlist */
  realmId: string;
  /** API base URL */
  apiUrl?: string;
  /** Referral code from URL or props */
  referralCode?: string;
  /** Custom class name */
  className?: string;
  /** Show position after signup */
  showPosition?: boolean;
  /** Show referral code after signup */
  showReferralCode?: boolean;
  /** Collect additional metadata */
  collectMetadata?: boolean;
  /** Custom fields to collect */
  customFields?: Array<{
    name: string;
    label: string;
    type: 'text' | 'textarea' | 'select';
    options?: string[];
    required?: boolean;
  }>;
  /** Callback when user joins waitlist */
  onJoin?: (result: WaitlistJoinResult) => void;
  /** Callback on error */
  onError?: (error: Error) => void;
  /** Custom success message */
  successMessage?: string;
  /** Custom button text */
  buttonText?: string;
  /** Custom title */
  title?: string;
  /** Custom description */
  description?: string;
  /** Compact mode */
  compact?: boolean;
}

// ============================================================================
// Styles
// ============================================================================

const styles = {
  container: {
    fontFamily: 'var(--zalt-font, system-ui, sans-serif)',
    color: 'var(--zalt-text, #fff)',
    maxWidth: '400px',
    margin: '0 auto',
  } as React.CSSProperties,

  card: {
    background: 'rgba(255,255,255,0.05)',
    borderRadius: 'var(--zalt-radius, 0.75rem)',
    padding: '24px',
    border: '1px solid rgba(255,255,255,0.1)',
  } as React.CSSProperties,

  title: {
    fontSize: '24px',
    fontWeight: 700,
    margin: '0 0 8px 0',
    textAlign: 'center' as const,
  } as React.CSSProperties,

  description: {
    fontSize: '14px',
    color: 'rgba(255,255,255,0.7)',
    margin: '0 0 24px 0',
    textAlign: 'center' as const,
  } as React.CSSProperties,

  form: {
    display: 'flex',
    flexDirection: 'column' as const,
    gap: '16px',
  } as React.CSSProperties,

  inputGroup: {
    display: 'flex',
    flexDirection: 'column' as const,
    gap: '6px',
  } as React.CSSProperties,

  label: {
    fontSize: '13px',
    fontWeight: 500,
    color: 'rgba(255,255,255,0.8)',
  } as React.CSSProperties,

  input: {
    padding: '12px 14px',
    background: 'rgba(255,255,255,0.1)',
    border: '1px solid rgba(255,255,255,0.2)',
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

  textarea: {
    padding: '12px 14px',
    background: 'rgba(255,255,255,0.1)',
    border: '1px solid rgba(255,255,255,0.2)',
    borderRadius: 'var(--zalt-radius, 0.5rem)',
    color: 'var(--zalt-text, #fff)',
    fontSize: '14px',
    outline: 'none',
    resize: 'vertical' as const,
    minHeight: '80px',
    fontFamily: 'inherit',
    width: '100%',
    boxSizing: 'border-box' as const,
  } as React.CSSProperties,

  select: {
    padding: '12px 14px',
    background: 'rgba(255,255,255,0.1)',
    border: '1px solid rgba(255,255,255,0.2)',
    borderRadius: 'var(--zalt-radius, 0.5rem)',
    color: 'var(--zalt-text, #fff)',
    fontSize: '14px',
    outline: 'none',
    cursor: 'pointer',
    width: '100%',
    boxSizing: 'border-box' as const,
  } as React.CSSProperties,

  row: {
    display: 'flex',
    gap: '12px',
  } as React.CSSProperties,

  button: {
    padding: '14px 24px',
    background: 'var(--zalt-primary, #10b981)',
    color: '#000',
    border: 'none',
    borderRadius: 'var(--zalt-radius, 0.5rem)',
    fontSize: '15px',
    fontWeight: 600,
    cursor: 'pointer',
    transition: 'opacity 0.15s, transform 0.1s',
    width: '100%',
  } as React.CSSProperties,

  buttonDisabled: {
    opacity: 0.6,
    cursor: 'not-allowed',
  } as React.CSSProperties,

  error: {
    padding: '12px 14px',
    background: 'rgba(239, 68, 68, 0.1)',
    border: '1px solid rgba(239, 68, 68, 0.3)',
    borderRadius: 'var(--zalt-radius, 0.5rem)',
    color: '#ef4444',
    fontSize: '13px',
  } as React.CSSProperties,

  success: {
    textAlign: 'center' as const,
  } as React.CSSProperties,

  successIcon: {
    width: '64px',
    height: '64px',
    margin: '0 auto 16px',
    background: 'rgba(16, 185, 129, 0.1)',
    borderRadius: '50%',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
  } as React.CSSProperties,

  successTitle: {
    fontSize: '20px',
    fontWeight: 600,
    margin: '0 0 8px 0',
  } as React.CSSProperties,

  successMessage: {
    fontSize: '14px',
    color: 'rgba(255,255,255,0.7)',
    margin: '0 0 24px 0',
  } as React.CSSProperties,

  positionCard: {
    background: 'rgba(255,255,255,0.05)',
    borderRadius: 'var(--zalt-radius, 0.5rem)',
    padding: '16px',
    marginBottom: '16px',
    textAlign: 'center' as const,
  } as React.CSSProperties,

  positionNumber: {
    fontSize: '48px',
    fontWeight: 700,
    color: 'var(--zalt-primary, #10b981)',
    lineHeight: 1,
  } as React.CSSProperties,

  positionLabel: {
    fontSize: '13px',
    color: 'rgba(255,255,255,0.6)',
    marginTop: '4px',
  } as React.CSSProperties,

  referralCard: {
    background: 'rgba(255,255,255,0.05)',
    borderRadius: 'var(--zalt-radius, 0.5rem)',
    padding: '16px',
    textAlign: 'center' as const,
  } as React.CSSProperties,

  referralLabel: {
    fontSize: '12px',
    color: 'rgba(255,255,255,0.6)',
    marginBottom: '8px',
  } as React.CSSProperties,

  referralCode: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '8px',
  } as React.CSSProperties,

  referralCodeText: {
    fontSize: '18px',
    fontWeight: 600,
    fontFamily: 'monospace',
    letterSpacing: '2px',
  } as React.CSSProperties,

  copyButton: {
    padding: '6px 12px',
    background: 'rgba(255,255,255,0.1)',
    border: '1px solid rgba(255,255,255,0.2)',
    borderRadius: 'var(--zalt-radius, 0.25rem)',
    color: 'var(--zalt-text, #fff)',
    fontSize: '12px',
    cursor: 'pointer',
    transition: 'background 0.15s',
  } as React.CSSProperties,

  referralHint: {
    fontSize: '12px',
    color: 'rgba(255,255,255,0.5)',
    marginTop: '12px',
  } as React.CSSProperties,
};

// ============================================================================
// Helper Components
// ============================================================================

function CheckIcon(): JSX.Element {
  return (
    <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#10b981" strokeWidth="2">
      <polyline points="20 6 9 17 4 12" />
    </svg>
  );
}

function LoadingSpinner(): JSX.Element {
  return (
    <svg
      width="20"
      height="20"
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
      />
    </svg>
  );
}

// ============================================================================
// Main Component
// ============================================================================

/**
 * Waitlist component for collecting signups before launch
 * 
 * @example
 * ```tsx
 * import { Waitlist } from '@zalt/react';
 * 
 * function WaitlistPage() {
 *   return (
 *     <Waitlist
 *       realmId="your-realm-id"
 *       title="Join the Waitlist"
 *       description="Be the first to know when we launch."
 *       showPosition
 *       showReferralCode
 *       onJoin={(result) => console.log('Joined:', result)}
 *     />
 *   );
 * }
 * ```
 */
export function Waitlist({
  realmId,
  apiUrl = 'https://api.zalt.io',
  referralCode: initialReferralCode,
  className = '',
  showPosition = true,
  showReferralCode = true,
  collectMetadata = false,
  customFields = [],
  onJoin,
  onError,
  successMessage = "You're on the list! We'll notify you when it's your turn.",
  buttonText = 'Join Waitlist',
  title = 'Join the Waitlist',
  description = "We're launching soon. Sign up to be notified.",
  compact = false,
}: WaitlistProps): JSX.Element {
  // Form state
  const [email, setEmail] = useState('');
  const [firstName, setFirstName] = useState('');
  const [lastName, setLastName] = useState('');
  const [company, setCompany] = useState('');
  const [useCase, setUseCase] = useState('');
  const [customFieldValues, setCustomFieldValues] = useState<Record<string, string>>({});
  const [referralCodeInput, setReferralCodeInput] = useState(initialReferralCode || '');

  // UI state
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<WaitlistJoinResult | null>(null);
  const [copied, setCopied] = useState(false);
  const [focusedField, setFocusedField] = useState<string | null>(null);

  // Get referral code from URL on mount
  useEffect(() => {
    if (typeof window !== 'undefined' && !initialReferralCode) {
      const params = new URLSearchParams(window.location.search);
      const ref = params.get('ref') || params.get('referral');
      if (ref) {
        setReferralCodeInput(ref);
      }
    }
  }, [initialReferralCode]);

  /**
   * Handle form submission
   */
  const handleSubmit = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    // Validate email
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      setError('Please enter a valid email address');
      return;
    }

    setIsSubmitting(true);

    try {
      const response = await fetch(`${apiUrl}/waitlist?realm_id=${realmId}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          email: email.trim().toLowerCase(),
          referral_code: referralCodeInput || undefined,
          metadata: collectMetadata ? {
            first_name: firstName || undefined,
            last_name: lastName || undefined,
            company: company || undefined,
            use_case: useCase || undefined,
            custom_fields: Object.keys(customFieldValues).length > 0 ? customFieldValues : undefined,
          } : undefined,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error?.message || 'Failed to join waitlist');
      }

      const joinResult: WaitlistJoinResult = {
        entry_id: data.data.entry_id,
        position: data.data.position,
        referral_code: data.data.referral_code,
        message: data.data.message || successMessage,
      };

      setResult(joinResult);
      onJoin?.(joinResult);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to join waitlist';
      setError(errorMessage);
      onError?.(err instanceof Error ? err : new Error(errorMessage));
    } finally {
      setIsSubmitting(false);
    }
  }, [email, firstName, lastName, company, useCase, customFieldValues, referralCodeInput, realmId, apiUrl, collectMetadata, successMessage, onJoin, onError]);

  /**
   * Copy referral code to clipboard
   */
  const handleCopyReferralCode = useCallback(async () => {
    if (result?.referral_code) {
      try {
        await navigator.clipboard.writeText(result.referral_code);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      } catch {
        // Fallback for older browsers
        const textArea = document.createElement('textarea');
        textArea.value = result.referral_code;
        document.body.appendChild(textArea);
        textArea.select();
        document.execCommand('copy');
        document.body.removeChild(textArea);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      }
    }
  }, [result?.referral_code]);

  /**
   * Get input style with focus state
   */
  const getInputStyle = (fieldName: string) => ({
    ...styles.input,
    ...(focusedField === fieldName ? styles.inputFocus : {}),
  });

  // Success state
  if (result) {
    return (
      <div className={`zalt-waitlist ${className}`} style={styles.container}>
        <div style={styles.card}>
          <div style={styles.success}>
            <div style={styles.successIcon}>
              <CheckIcon />
            </div>
            <h2 style={styles.successTitle}>You're on the list!</h2>
            <p style={styles.successMessage}>{result.message}</p>

            {showPosition && (
              <div style={styles.positionCard}>
                <div style={styles.positionNumber}>#{result.position}</div>
                <div style={styles.positionLabel}>Your position in line</div>
              </div>
            )}

            {showReferralCode && result.referral_code && (
              <div style={styles.referralCard}>
                <div style={styles.referralLabel}>Share your referral code to move up</div>
                <div style={styles.referralCode}>
                  <span style={styles.referralCodeText}>{result.referral_code}</span>
                  <button
                    onClick={handleCopyReferralCode}
                    style={styles.copyButton}
                    aria-label="Copy referral code"
                  >
                    {copied ? 'Copied!' : 'Copy'}
                  </button>
                </div>
                <p style={styles.referralHint}>
                  Each friend who joins using your code moves you up in line
                </p>
              </div>
            )}
          </div>
        </div>
      </div>
    );
  }

  // Form state
  return (
    <div className={`zalt-waitlist ${className}`} style={styles.container}>
      <div style={styles.card}>
        {!compact && (
          <>
            <h2 style={styles.title}>{title}</h2>
            <p style={styles.description}>{description}</p>
          </>
        )}

        {error && (
          <div style={{ ...styles.error, marginBottom: '16px' }}>
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} style={styles.form}>
          <div style={styles.inputGroup}>
            <label htmlFor="waitlist-email" style={styles.label}>
              Email address
            </label>
            <input
              id="waitlist-email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              onFocus={() => setFocusedField('email')}
              onBlur={() => setFocusedField(null)}
              placeholder="you@example.com"
              style={getInputStyle('email')}
              disabled={isSubmitting}
              required
              autoComplete="email"
            />
          </div>

          {collectMetadata && (
            <>
              <div style={styles.row}>
                <div style={{ ...styles.inputGroup, flex: 1 }}>
                  <label htmlFor="waitlist-firstname" style={styles.label}>
                    First name
                  </label>
                  <input
                    id="waitlist-firstname"
                    type="text"
                    value={firstName}
                    onChange={(e) => setFirstName(e.target.value)}
                    onFocus={() => setFocusedField('firstName')}
                    onBlur={() => setFocusedField(null)}
                    placeholder="John"
                    style={getInputStyle('firstName')}
                    disabled={isSubmitting}
                    autoComplete="given-name"
                  />
                </div>
                <div style={{ ...styles.inputGroup, flex: 1 }}>
                  <label htmlFor="waitlist-lastname" style={styles.label}>
                    Last name
                  </label>
                  <input
                    id="waitlist-lastname"
                    type="text"
                    value={lastName}
                    onChange={(e) => setLastName(e.target.value)}
                    onFocus={() => setFocusedField('lastName')}
                    onBlur={() => setFocusedField(null)}
                    placeholder="Doe"
                    style={getInputStyle('lastName')}
                    disabled={isSubmitting}
                    autoComplete="family-name"
                  />
                </div>
              </div>

              <div style={styles.inputGroup}>
                <label htmlFor="waitlist-company" style={styles.label}>
                  Company (optional)
                </label>
                <input
                  id="waitlist-company"
                  type="text"
                  value={company}
                  onChange={(e) => setCompany(e.target.value)}
                  onFocus={() => setFocusedField('company')}
                  onBlur={() => setFocusedField(null)}
                  placeholder="Acme Inc."
                  style={getInputStyle('company')}
                  disabled={isSubmitting}
                  autoComplete="organization"
                />
              </div>

              <div style={styles.inputGroup}>
                <label htmlFor="waitlist-usecase" style={styles.label}>
                  How will you use this? (optional)
                </label>
                <textarea
                  id="waitlist-usecase"
                  value={useCase}
                  onChange={(e) => setUseCase(e.target.value)}
                  placeholder="Tell us about your use case..."
                  style={styles.textarea}
                  disabled={isSubmitting}
                />
              </div>
            </>
          )}

          {/* Custom fields */}
          {customFields.map((field) => (
            <div key={field.name} style={styles.inputGroup}>
              <label htmlFor={`waitlist-${field.name}`} style={styles.label}>
                {field.label} {field.required && '*'}
              </label>
              {field.type === 'textarea' ? (
                <textarea
                  id={`waitlist-${field.name}`}
                  value={customFieldValues[field.name] || ''}
                  onChange={(e) => setCustomFieldValues(prev => ({
                    ...prev,
                    [field.name]: e.target.value,
                  }))}
                  style={styles.textarea}
                  disabled={isSubmitting}
                  required={field.required}
                />
              ) : field.type === 'select' ? (
                <select
                  id={`waitlist-${field.name}`}
                  value={customFieldValues[field.name] || ''}
                  onChange={(e) => setCustomFieldValues(prev => ({
                    ...prev,
                    [field.name]: e.target.value,
                  }))}
                  style={styles.select}
                  disabled={isSubmitting}
                  required={field.required}
                >
                  <option value="">Select...</option>
                  {field.options?.map((opt) => (
                    <option key={opt} value={opt}>{opt}</option>
                  ))}
                </select>
              ) : (
                <input
                  id={`waitlist-${field.name}`}
                  type="text"
                  value={customFieldValues[field.name] || ''}
                  onChange={(e) => setCustomFieldValues(prev => ({
                    ...prev,
                    [field.name]: e.target.value,
                  }))}
                  onFocus={() => setFocusedField(field.name)}
                  onBlur={() => setFocusedField(null)}
                  style={getInputStyle(field.name)}
                  disabled={isSubmitting}
                  required={field.required}
                />
              )}
            </div>
          ))}

          {/* Referral code input */}
          {!initialReferralCode && (
            <div style={styles.inputGroup}>
              <label htmlFor="waitlist-referral" style={styles.label}>
                Referral code (optional)
              </label>
              <input
                id="waitlist-referral"
                type="text"
                value={referralCodeInput}
                onChange={(e) => setReferralCodeInput(e.target.value.toUpperCase())}
                onFocus={() => setFocusedField('referral')}
                onBlur={() => setFocusedField(null)}
                placeholder="ABC12345"
                style={getInputStyle('referral')}
                disabled={isSubmitting}
                maxLength={8}
              />
            </div>
          )}

          <button
            type="submit"
            style={{
              ...styles.button,
              ...(isSubmitting ? styles.buttonDisabled : {}),
            }}
            disabled={isSubmitting}
          >
            {isSubmitting ? (
              <span style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px' }}>
                <LoadingSpinner />
                Joining...
              </span>
            ) : (
              buttonText
            )}
          </button>
        </form>
      </div>
    </div>
  );
}

export default Waitlist;
