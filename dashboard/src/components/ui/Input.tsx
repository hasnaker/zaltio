'use client';

import React, { forwardRef, InputHTMLAttributes, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { AlertCircle, CheckCircle2, Eye, EyeOff } from 'lucide-react';
import { cn } from '@/lib/utils';

export type InputSize = 'sm' | 'md' | 'lg';
export type InputState = 'default' | 'error' | 'success';

export interface InputProps extends Omit<InputHTMLAttributes<HTMLInputElement>, 'size'> {
  size?: InputSize;
  state?: InputState;
  label?: string;
  helperText?: string;
  errorMessage?: string;
  successMessage?: string;
  leftIcon?: React.ReactNode;
  rightIcon?: React.ReactNode;
  showPasswordToggle?: boolean;
  fullWidth?: boolean;
}

const sizeStyles: Record<InputSize, string> = {
  sm: 'h-9 px-3 text-sm rounded-lg',
  md: 'h-11 px-4 text-base rounded-xl',
  lg: 'h-13 px-5 text-lg rounded-xl',
};

const iconSizes: Record<InputSize, number> = {
  sm: 14,
  md: 18,
  lg: 20,
};

const stateStyles: Record<InputState, string> = {
  default: `
    border-neutral-200 
    hover:border-neutral-300 
    focus:border-primary focus:ring-2 focus:ring-primary/20
  `,
  error: `
    border-error 
    hover:border-error 
    focus:border-error focus:ring-2 focus:ring-error/20
  `,
  success: `
    border-success 
    hover:border-success 
    focus:border-success focus:ring-2 focus:ring-success/20
  `,
};

export const Input = forwardRef<HTMLInputElement, InputProps>(
  (
    {
      size = 'md',
      state = 'default',
      label,
      helperText,
      errorMessage,
      successMessage,
      leftIcon,
      rightIcon,
      showPasswordToggle = false,
      fullWidth = false,
      type = 'text',
      className,
      disabled,
      id,
      onFocus,
      onBlur,
      ...props
    },
    ref
  ) => {
    const [showPassword, setShowPassword] = useState(false);
    const [isFocused, setIsFocused] = useState(false);

    const inputId = id || `input-${Math.random().toString(36).substr(2, 9)}`;
    const isPassword = type === 'password';
    const inputType = isPassword && showPassword ? 'text' : type;

    // Determine actual state based on messages
    const actualState = errorMessage ? 'error' : successMessage ? 'success' : state;
    const message = errorMessage || successMessage || helperText;

    const hasLeftIcon = !!leftIcon;
    const hasRightIcon = !!rightIcon || (isPassword && showPasswordToggle) || actualState !== 'default';

    const handleFocus = (e: React.FocusEvent<HTMLInputElement>) => {
      setIsFocused(true);
      onFocus?.(e);
    };

    const handleBlur = (e: React.FocusEvent<HTMLInputElement>) => {
      setIsFocused(false);
      onBlur?.(e);
    };

    return (
      <div className={cn('flex flex-col gap-1.5', fullWidth && 'w-full')}>
        {/* Label */}
        {label && (
          <label
            htmlFor={inputId}
            className="text-sm font-medium text-neutral-700"
          >
            {label}
          </label>
        )}

        {/* Input wrapper */}
        <div className="relative">
          {/* Left icon */}
          {hasLeftIcon && (
            <div className="absolute left-3 top-1/2 -translate-y-1/2 text-neutral-400">
              {leftIcon}
            </div>
          )}

          {/* Input */}
          <input
            ref={ref}
            id={inputId}
            type={inputType}
            disabled={disabled}
            className={cn(
              // Base styles
              'w-full bg-white border outline-none transition-all duration-200',
              // Size styles
              sizeStyles[size],
              // State styles
              stateStyles[actualState],
              // Icon padding
              hasLeftIcon && 'pl-10',
              hasRightIcon && 'pr-10',
              // Disabled styles
              disabled && 'opacity-50 cursor-not-allowed bg-neutral-50',
              // Focus shadow
              isFocused && actualState === 'error' && 'shadow-[0_0_0_3px_rgba(239,68,68,0.2)]',
              isFocused && actualState === 'success' && 'shadow-[0_0_0_3px_rgba(34,197,94,0.2)]',
              isFocused && actualState === 'default' && 'shadow-[0_0_0_3px_rgba(108,71,255,0.2)]',
              className
            )}
            onFocus={handleFocus}
            onBlur={handleBlur}
            {...props}
          />

          {/* Right side icons */}
          <div className="absolute right-3 top-1/2 -translate-y-1/2 flex items-center gap-2">
            {/* State icon */}
            {actualState === 'error' && (
              <AlertCircle size={iconSizes[size]} className="text-error" />
            )}
            {actualState === 'success' && (
              <CheckCircle2 size={iconSizes[size]} className="text-success" />
            )}

            {/* Password toggle */}
            {isPassword && showPasswordToggle && (
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                aria-label={showPassword ? 'Hide password' : 'Show password'}
                aria-pressed={showPassword}
                className="text-neutral-400 hover:text-neutral-600 transition-colors"
                tabIndex={-1}
              >
                {showPassword ? (
                  <EyeOff size={iconSizes[size]} aria-hidden="true" />
                ) : (
                  <Eye size={iconSizes[size]} aria-hidden="true" />
                )}
              </button>
            )}

            {/* Custom right icon */}
            {rightIcon && !isPassword && actualState === 'default' && (
              <span className="text-neutral-400">{rightIcon}</span>
            )}
          </div>
        </div>

        {/* Helper/Error/Success message */}
        <AnimatePresence mode="wait">
          {message && (
            <motion.p
              initial={{ opacity: 0, y: -5 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -5 }}
              transition={{ duration: 0.15 }}
              className={cn(
                'text-sm',
                actualState === 'error' && 'text-error',
                actualState === 'success' && 'text-success',
                actualState === 'default' && 'text-neutral-500'
              )}
            >
              {message}
            </motion.p>
          )}
        </AnimatePresence>
      </div>
    );
  }
);

Input.displayName = 'Input';

// Textarea variant
export interface TextareaProps extends Omit<React.TextareaHTMLAttributes<HTMLTextAreaElement>, 'size'> {
  size?: InputSize;
  state?: InputState;
  label?: string;
  helperText?: string;
  errorMessage?: string;
  successMessage?: string;
  fullWidth?: boolean;
}

export const Textarea = forwardRef<HTMLTextAreaElement, TextareaProps>(
  (
    {
      size = 'md',
      state = 'default',
      label,
      helperText,
      errorMessage,
      successMessage,
      fullWidth = false,
      className,
      disabled,
      id,
      onFocus,
      onBlur,
      ...props
    },
    ref
  ) => {
    const [isFocused, setIsFocused] = useState(false);
    const inputId = id || `textarea-${Math.random().toString(36).substr(2, 9)}`;
    
    const actualState = errorMessage ? 'error' : successMessage ? 'success' : state;
    const message = errorMessage || successMessage || helperText;

    const textareaSizeStyles: Record<InputSize, string> = {
      sm: 'px-3 py-2 text-sm rounded-lg',
      md: 'px-4 py-3 text-base rounded-xl',
      lg: 'px-5 py-4 text-lg rounded-xl',
    };

    const handleFocus = (e: React.FocusEvent<HTMLTextAreaElement>) => {
      setIsFocused(true);
      onFocus?.(e);
    };

    const handleBlur = (e: React.FocusEvent<HTMLTextAreaElement>) => {
      setIsFocused(false);
      onBlur?.(e);
    };

    return (
      <div className={cn('flex flex-col gap-1.5', fullWidth && 'w-full')}>
        {label && (
          <label
            htmlFor={inputId}
            className="text-sm font-medium text-neutral-700"
          >
            {label}
          </label>
        )}

        <textarea
          ref={ref}
          id={inputId}
          disabled={disabled}
          className={cn(
            'w-full bg-white border outline-none transition-all duration-200 resize-y min-h-[100px]',
            textareaSizeStyles[size],
            stateStyles[actualState],
            disabled && 'opacity-50 cursor-not-allowed bg-neutral-50',
            isFocused && actualState === 'error' && 'shadow-[0_0_0_3px_rgba(239,68,68,0.2)]',
            isFocused && actualState === 'success' && 'shadow-[0_0_0_3px_rgba(34,197,94,0.2)]',
            isFocused && actualState === 'default' && 'shadow-[0_0_0_3px_rgba(108,71,255,0.2)]',
            className
          )}
          onFocus={handleFocus}
          onBlur={handleBlur}
          {...props}
        />

        <AnimatePresence mode="wait">
          {message && (
            <motion.p
              initial={{ opacity: 0, y: -5 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -5 }}
              transition={{ duration: 0.15 }}
              className={cn(
                'text-sm',
                actualState === 'error' && 'text-error',
                actualState === 'success' && 'text-success',
                actualState === 'default' && 'text-neutral-500'
              )}
            >
              {message}
            </motion.p>
          )}
        </AnimatePresence>
      </div>
    );
  }
);

Textarea.displayName = 'Textarea';

export default Input;
