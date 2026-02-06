'use client';

import React, { forwardRef, ButtonHTMLAttributes } from 'react';
import { motion, HTMLMotionProps } from 'framer-motion';
import { Loader2 } from 'lucide-react';
import { cn } from '@/lib/utils';
import { microInteractions, springs } from '@/lib/motion';

export type ButtonVariant = 'primary' | 'secondary' | 'outline' | 'ghost' | 'gradient' | 'glass';
export type ButtonSize = 'sm' | 'md' | 'lg' | 'xl';

export interface ButtonProps extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'onAnimationStart' | 'onDrag' | 'onDragEnd' | 'onDragStart'> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  leftIcon?: React.ReactNode;
  rightIcon?: React.ReactNode;
  isLoading?: boolean;
  fullWidth?: boolean;
  magnetic?: boolean;
  glow?: boolean;
  children: React.ReactNode;
}

const variantStyles: Record<ButtonVariant, string> = {
  primary: `
    bg-gradient-to-r from-primary to-primary-600 
    text-white font-semibold
    shadow-button
    hover:shadow-button-hover hover:from-primary-600 hover:to-primary-700
    active:shadow-button
  `,
  secondary: `
    bg-white text-neutral-700 
    border border-neutral-200
    hover:border-primary/30 hover:bg-primary-50/50 hover:text-primary
    active:bg-primary-50
  `,
  outline: `
    bg-transparent text-primary 
    border-2 border-primary
    hover:bg-primary hover:text-white
    active:bg-primary-700
  `,
  ghost: `
    bg-transparent text-neutral-600
    hover:bg-neutral-100 hover:text-neutral-900
    active:bg-neutral-200
  `,
  gradient: `
    bg-gradient-to-r from-primary via-primary-500 to-accent 
    text-white font-semibold
    shadow-button
    hover:shadow-button-hover
    active:shadow-button
    bg-[length:200%_100%]
    hover:bg-right
  `,
  glass: `
    bg-white/10 backdrop-blur-md 
    text-white border border-white/20
    hover:bg-white/20 hover:border-white/30
    active:bg-white/25
  `,
};

const sizeStyles: Record<ButtonSize, string> = {
  sm: 'px-3 py-1.5 text-sm rounded-lg gap-1.5',
  md: 'px-4 py-2 text-sm rounded-xl gap-2',
  lg: 'px-6 py-3 text-base rounded-xl gap-2',
  xl: 'px-8 py-4 text-lg rounded-2xl gap-3',
};

const iconSizes: Record<ButtonSize, number> = {
  sm: 14,
  md: 16,
  lg: 18,
  xl: 20,
};

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  (
    {
      variant = 'primary',
      size = 'md',
      leftIcon,
      rightIcon,
      isLoading = false,
      fullWidth = false,
      magnetic = false,
      glow = false,
      disabled,
      className,
      children,
      ...props
    },
    ref
  ) => {
    const isDisabled = disabled || isLoading;

    // Motion props for magnetic hover effect
    const motionProps = magnetic
      ? {
          whileHover: { scale: 1.02, y: -2 },
          whileTap: { scale: 0.98 },
          transition: springs.snappy,
        }
      : {
          whileHover: { scale: 1.01 },
          whileTap: { scale: 0.99 },
          transition: springs.snappy,
        };

    return (
      <motion.button
        ref={ref}
        disabled={isDisabled}
        className={cn(
          // Base styles
          'inline-flex items-center justify-center font-medium',
          'transition-all duration-200 ease-out',
          'focus:outline-none focus-visible:ring-2 focus-visible:ring-primary/40 focus-visible:ring-offset-2',
          'disabled:opacity-50 disabled:cursor-not-allowed disabled:pointer-events-none',
          // Variant styles
          variantStyles[variant],
          // Size styles
          sizeStyles[size],
          // Full width
          fullWidth && 'w-full',
          // Glow effect
          glow && 'shadow-glow hover:shadow-glow-md',
          className
        )}
        {...motionProps}
        {...(props as HTMLMotionProps<'button'>)}
      >
        {/* Loading spinner */}
        {isLoading && (
          <Loader2 
            size={iconSizes[size]} 
            className="animate-spin" 
          />
        )}
        
        {/* Left icon */}
        {!isLoading && leftIcon && (
          <span className="flex-shrink-0">{leftIcon}</span>
        )}
        
        {/* Children */}
        <span>{children}</span>
        
        {/* Right icon */}
        {!isLoading && rightIcon && (
          <span className="flex-shrink-0">{rightIcon}</span>
        )}
      </motion.button>
    );
  }
);

Button.displayName = 'Button';

// Icon Button variant
export interface IconButtonProps extends Omit<ButtonProps, 'leftIcon' | 'rightIcon' | 'children'> {
  icon: React.ReactNode;
  'aria-label': string;
}

export const IconButton = forwardRef<HTMLButtonElement, IconButtonProps>(
  ({ icon, size = 'md', className, ...props }, ref) => {
    const iconSizeStyles: Record<ButtonSize, string> = {
      sm: 'p-1.5',
      md: 'p-2',
      lg: 'p-2.5',
      xl: 'p-3',
    };

    return (
      <Button
        ref={ref}
        size={size}
        className={cn(iconSizeStyles[size], 'aspect-square', className)}
        {...props}
      >
        {icon}
      </Button>
    );
  }
);

IconButton.displayName = 'IconButton';

export default Button;
