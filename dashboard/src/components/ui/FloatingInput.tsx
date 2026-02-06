'use client';

import React, { useState, useId } from 'react';

export type FloatingInputType = 'text' | 'email' | 'password';

export interface FloatingInputProps {
  label: string;
  type?: FloatingInputType;
  value: string;
  onChange: (value: string) => void;
  error?: string;
  icon?: React.ReactNode;
  disabled?: boolean;
  required?: boolean;
  className?: string;
  name?: string;
  autoComplete?: string;
}

/**
 * FloatingInput Component
 * 
 * An input component with floating label animation, focus glow effects,
 * error state support, and optional icon.
 * 
 * Requirements: 3.3, 8.4
 */
export function FloatingInput({
  label,
  type = 'text',
  value,
  onChange,
  error,
  icon,
  disabled = false,
  required = false,
  className = '',
  name,
  autoComplete,
}: FloatingInputProps) {
  const [isFocused, setIsFocused] = useState(false);
  const inputId = useId();
  
  const hasValue = value.length > 0;
  const isLabelFloating = isFocused || hasValue;
  
  const containerClasses = [
    'relative',
    className,
  ].filter(Boolean).join(' ');
  
  const inputClasses = [
    'w-full px-4 py-3 bg-nexus-cosmic-nebula/50 border rounded-lg',
    'text-nexus-text-primary placeholder-transparent',
    'transition-all duration-300',
    'focus:outline-none',
    icon ? 'pl-11' : '',
    error
      ? 'border-nexus-error focus:border-nexus-error focus:ring-2 focus:ring-nexus-error/30'
      : 'border-white/10 focus:border-nexus-glow-cyan focus:ring-2 focus:ring-nexus-glow-cyan/30 focus:shadow-glow-cyan',
    disabled ? 'opacity-50 cursor-not-allowed' : '',
  ].filter(Boolean).join(' ');
  
  const labelClasses = [
    'absolute left-4 transition-all duration-300 pointer-events-none',
    icon ? 'left-11' : 'left-4',
    isLabelFloating
      ? '-top-2.5 text-xs bg-nexus-cosmic-deep px-1'
      : 'top-3 text-base',
    error
      ? 'text-nexus-error'
      : isFocused
        ? 'text-nexus-glow-cyan'
        : 'text-nexus-text-muted',
  ].filter(Boolean).join(' ');
  
  const iconClasses = [
    'absolute left-4 top-1/2 -translate-y-1/2 transition-colors duration-300',
    error
      ? 'text-nexus-error'
      : isFocused
        ? 'text-nexus-glow-cyan'
        : 'text-nexus-text-muted',
  ].join(' ');
  
  return (
    <div className={containerClasses}>
      <div className="relative">
        {icon && (
          <span className={iconClasses} data-testid="input-icon">
            {icon}
          </span>
        )}
        
        <input
          id={inputId}
          type={type}
          name={name}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          onFocus={() => setIsFocused(true)}
          onBlur={() => setIsFocused(false)}
          disabled={disabled}
          required={required}
          autoComplete={autoComplete}
          className={inputClasses}
          placeholder={label}
          aria-invalid={!!error}
          aria-describedby={error ? `${inputId}-error` : undefined}
          data-focused={isFocused}
          data-has-value={hasValue}
          data-has-error={!!error}
        />
        
        <label htmlFor={inputId} className={labelClasses}>
          {label}
          {required && <span className="text-nexus-error ml-1">*</span>}
        </label>
      </div>
      
      {error && (
        <p
          id={`${inputId}-error`}
          className="mt-1.5 text-sm text-nexus-error animate-fade-in-up"
          role="alert"
        >
          {error}
        </p>
      )}
    </div>
  );
}

export default FloatingInput;
