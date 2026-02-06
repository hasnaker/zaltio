/**
 * Auth Button Components
 * @zalt/react
 */

'use client';

import React, { type ReactNode, type ButtonHTMLAttributes } from 'react';

/**
 * Base button props
 */
export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  /** Button variant */
  variant?: 'primary' | 'secondary' | 'outline';
  /** Button size */
  size?: 'sm' | 'md' | 'lg';
  /** Loading state */
  loading?: boolean;
  /** Icon to show */
  icon?: ReactNode;
  /** Full width */
  fullWidth?: boolean;
}

const sizeStyles = {
  sm: { padding: '8px 16px', fontSize: '13px' },
  md: { padding: '10px 20px', fontSize: '14px' },
  lg: { padding: '12px 24px', fontSize: '16px' },
};

/**
 * Base button component with Zalt styling
 */
function ZaltButton({
  children,
  variant = 'primary',
  size = 'md',
  loading = false,
  icon,
  fullWidth = false,
  disabled,
  style,
  ...props
}: ButtonProps): JSX.Element {
  const baseStyle: React.CSSProperties = {
    display: 'inline-flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '8px',
    fontWeight: 600,
    borderRadius: 'var(--zalt-radius, 0.5rem)',
    cursor: disabled || loading ? 'not-allowed' : 'pointer',
    opacity: disabled || loading ? 0.6 : 1,
    transition: 'all 0.15s ease',
    width: fullWidth ? '100%' : 'auto',
    ...sizeStyles[size],
  };

  const variantStyles: Record<string, React.CSSProperties> = {
    primary: {
      background: 'var(--zalt-primary, #10b981)',
      color: '#000',
      border: 'none',
    },
    secondary: {
      background: 'rgba(16, 185, 129, 0.1)',
      color: 'var(--zalt-primary, #10b981)',
      border: '1px solid var(--zalt-primary, #10b981)',
    },
    outline: {
      background: 'transparent',
      color: 'var(--zalt-text, #fff)',
      border: '1px solid rgba(255,255,255,0.2)',
    },
  };

  return (
    <button
      {...props}
      disabled={disabled || loading}
      style={{ ...baseStyle, ...variantStyles[variant], ...style }}
    >
      {loading ? (
        <LoadingSpinner />
      ) : (
        <>
          {icon}
          {children}
        </>
      )}
    </button>
  );
}

function LoadingSpinner() {
  return (
    <svg
      width="16"
      height="16"
      viewBox="0 0 16 16"
      fill="none"
      style={{ animation: 'zalt-spin 1s linear infinite' }}
    >
      <style>{`@keyframes zalt-spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }`}</style>
      <circle
        cx="8"
        cy="8"
        r="6"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeDasharray="32"
        strokeDashoffset="8"
      />
    </svg>
  );
}

/**
 * Sign In Button
 */
export interface SignInButtonProps extends Omit<ButtonProps, 'children'> {
  /** Button text */
  children?: ReactNode;
  /** Redirect URL after sign in */
  redirectUrl?: string;
  /** Click handler - if provided, overrides default behavior */
  onClick?: () => void;
}

export function SignInButton({
  children = 'Sign In',
  redirectUrl,
  onClick,
  ...props
}: SignInButtonProps): JSX.Element {
  const handleClick = () => {
    if (onClick) {
      onClick();
    } else if (redirectUrl) {
      window.location.href = redirectUrl;
    }
  };

  return (
    <ZaltButton onClick={handleClick} variant="primary" {...props}>
      {children}
    </ZaltButton>
  );
}

/**
 * Sign Up Button
 */
export interface SignUpButtonProps extends Omit<ButtonProps, 'children'> {
  /** Button text */
  children?: ReactNode;
  /** Redirect URL after sign up */
  redirectUrl?: string;
  /** Click handler - if provided, overrides default behavior */
  onClick?: () => void;
}

export function SignUpButton({
  children = 'Sign Up',
  redirectUrl,
  onClick,
  ...props
}: SignUpButtonProps): JSX.Element {
  const handleClick = () => {
    if (onClick) {
      onClick();
    } else if (redirectUrl) {
      window.location.href = redirectUrl;
    }
  };

  return (
    <ZaltButton onClick={handleClick} variant="secondary" {...props}>
      {children}
    </ZaltButton>
  );
}

/**
 * Passkey Button - for WebAuthn authentication
 */
export interface PasskeyButtonProps extends Omit<ButtonProps, 'children'> {
  /** Button text */
  children?: ReactNode;
  /** Mode: register or authenticate */
  mode?: 'register' | 'authenticate';
  /** Click handler */
  onClick?: () => void;
}

export function PasskeyButton({
  children,
  mode = 'authenticate',
  onClick,
  ...props
}: PasskeyButtonProps): JSX.Element {
  const defaultText = mode === 'register' ? 'Add Passkey' : 'Sign in with Passkey';
  
  return (
    <ZaltButton onClick={onClick} variant="outline" {...props}>
      <PasskeyIcon />
      {children || defaultText}
    </ZaltButton>
  );
}

function PasskeyIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M12 11c0 3.517-1.009 6.799-2.753 9.571m-3.44-2.04l.054-.09A13.916 13.916 0 008 11a4 4 0 118 0c0 1.017-.07 2.019-.203 3m-2.118 6.844A21.88 21.88 0 0015.171 17m3.839 1.132c.645-2.266.99-4.659.99-7.132A8 8 0 008 4.07M3 15.364c.64-1.319 1-2.8 1-4.364 0-1.457.39-2.823 1.07-4" />
    </svg>
  );
}

export { ZaltButton };
export default ZaltButton;
