'use client';

import React from 'react';

export type GlowButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger';
export type GlowButtonSize = 'sm' | 'md' | 'lg';

export interface GlowButtonProps {
  children: React.ReactNode;
  variant?: GlowButtonVariant;
  size?: GlowButtonSize;
  glow?: boolean;
  loading?: boolean;
  disabled?: boolean;
  onClick?: () => void;
  type?: 'button' | 'submit' | 'reset';
  className?: string;
}

/**
 * GlowButton Component
 * 
 * A button component with glow effects, scale animations on hover,
 * and loading state support.
 * 
 * Requirements: 8.2
 */
export function GlowButton({
  children,
  variant = 'primary',
  size = 'md',
  glow = true,
  loading = false,
  disabled = false,
  onClick,
  type = 'button',
  className = '',
}: GlowButtonProps) {
  const baseClasses = 'font-medium rounded-lg transition-all duration-300 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-nexus-cosmic-black inline-flex items-center justify-center';
  
  const sizeClasses: Record<GlowButtonSize, string> = {
    sm: 'px-3 py-1.5 text-sm',
    md: 'px-4 py-2 text-base',
    lg: 'px-6 py-3 text-lg',
  };
  
  const variantClasses: Record<GlowButtonVariant, string> = {
    primary: 'bg-gradient-to-r from-nexus-glow-cyan to-nexus-glow-blue text-nexus-cosmic-black hover:scale-105 focus:ring-nexus-glow-cyan',
    secondary: 'bg-nexus-cosmic-nebula border border-nexus-glow-purple text-nexus-glow-purple hover:bg-nexus-glow-purple/10 hover:scale-105 focus:ring-nexus-glow-purple',
    ghost: 'bg-transparent text-nexus-text-secondary hover:text-nexus-text-primary hover:bg-white/5 hover:scale-105 focus:ring-white/20',
    danger: 'bg-nexus-error text-white hover:bg-nexus-error/80 hover:scale-105 focus:ring-nexus-error',
  };
  
  const glowClasses: Record<GlowButtonVariant, string> = {
    primary: 'hover:shadow-glow-cyan',
    secondary: 'hover:shadow-glow-purple',
    ghost: '',
    danger: 'hover:shadow-[0_0_20px_rgba(255,71,87,0.3)]',
  };
  
  const disabledClasses = 'opacity-50 cursor-not-allowed hover:scale-100 hover:shadow-none';
  
  const classes = [
    baseClasses,
    sizeClasses[size],
    variantClasses[variant],
    glow ? glowClasses[variant] : '',
    (disabled || loading) ? disabledClasses : '',
    className,
  ].filter(Boolean).join(' ');
  
  return (
    <button
      type={type}
      className={classes}
      onClick={onClick}
      disabled={disabled || loading}
      data-variant={variant}
      data-size={size}
      data-glow={glow}
      data-loading={loading}
    >
      {loading ? (
        <>
          <svg
            className="animate-spin -ml-1 mr-2 h-4 w-4"
            xmlns="http://www.w3.org/2000/svg"
            fill="none"
            viewBox="0 0 24 24"
          >
            <circle
              className="opacity-25"
              cx="12"
              cy="12"
              r="10"
              stroke="currentColor"
              strokeWidth="4"
            />
            <path
              className="opacity-75"
              fill="currentColor"
              d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
            />
          </svg>
          Loading...
        </>
      ) : (
        children
      )}
    </button>
  );
}

export default GlowButton;
