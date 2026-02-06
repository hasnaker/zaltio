'use client';

import React, { forwardRef, useState } from 'react';
import { cn } from '../utils/cn';
import { Eye, EyeOff } from 'lucide-react';

export interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  error?: string;
  label?: string;
  hint?: string;
}

const Input = forwardRef<HTMLInputElement, InputProps>(
  ({ className, type, error, label, hint, id, ...props }, ref) => {
    const [showPassword, setShowPassword] = useState(false);
    const inputId = id || `input-${Math.random().toString(36).slice(2, 9)}`;
    const isPassword = type === 'password';
    const inputType = isPassword && showPassword ? 'text' : type;

    return (
      <div className="w-full">
        {label && (
          <label
            htmlFor={inputId}
            className="block text-sm font-medium text-[var(--zalt-foreground)] mb-1.5"
          >
            {label}
          </label>
        )}
        <div className="relative">
          <input
            type={inputType}
            id={inputId}
            className={cn(
              'flex h-10 w-full rounded-md border bg-[var(--zalt-input)] px-3 py-2 text-sm text-[var(--zalt-input-foreground)] placeholder:text-[var(--zalt-input-placeholder)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50',
              error
                ? 'border-[var(--zalt-error)] focus-visible:ring-[var(--zalt-error)]'
                : 'border-[var(--zalt-input-border)] focus-visible:ring-[var(--zalt-input-focus)]',
              isPassword && 'pr-10',
              className
            )}
            ref={ref}
            aria-invalid={!!error}
            aria-describedby={error ? `${inputId}-error` : hint ? `${inputId}-hint` : undefined}
            {...props}
          />
          {isPassword && (
            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-[var(--zalt-muted-foreground)] hover:text-[var(--zalt-foreground)] focus:outline-none"
              tabIndex={-1}
              aria-label={showPassword ? 'Hide password' : 'Show password'}
            >
              {showPassword ? (
                <EyeOff className="h-4 w-4" />
              ) : (
                <Eye className="h-4 w-4" />
              )}
            </button>
          )}
        </div>
        {error && (
          <p id={`${inputId}-error`} className="mt-1.5 text-sm text-[var(--zalt-error)]">
            {error}
          </p>
        )}
        {hint && !error && (
          <p id={`${inputId}-hint`} className="mt-1.5 text-sm text-[var(--zalt-muted-foreground)]">
            {hint}
          </p>
        )}
      </div>
    );
  }
);
Input.displayName = 'Input';

export { Input };
