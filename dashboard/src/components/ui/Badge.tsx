'use client';

import React, { forwardRef, HTMLAttributes } from 'react';
import { motion } from 'framer-motion';
import { cn } from '@/lib/utils';

export type BadgeVariant = 'success' | 'warning' | 'error' | 'info' | 'neutral' | 'primary';
export type BadgeSize = 'sm' | 'md' | 'lg';

export interface BadgeProps extends HTMLAttributes<HTMLSpanElement> {
  variant?: BadgeVariant;
  size?: BadgeSize;
  dot?: boolean;
  pulse?: boolean;
  icon?: React.ReactNode;
  children: React.ReactNode;
}

const variantStyles: Record<BadgeVariant, string> = {
  success: 'bg-success-50 text-success-700 border-success-200',
  warning: 'bg-warning-50 text-warning-700 border-warning-200',
  error: 'bg-error-50 text-error-700 border-error-200',
  info: 'bg-info-50 text-info-700 border-info-200',
  neutral: 'bg-neutral-100 text-neutral-600 border-neutral-200',
  primary: 'bg-primary-50 text-primary-700 border-primary-200',
};

const dotColors: Record<BadgeVariant, string> = {
  success: 'bg-success',
  warning: 'bg-warning',
  error: 'bg-error',
  info: 'bg-info',
  neutral: 'bg-neutral-400',
  primary: 'bg-primary',
};

const sizeStyles: Record<BadgeSize, string> = {
  sm: 'px-2 py-0.5 text-xs gap-1',
  md: 'px-2.5 py-1 text-sm gap-1.5',
  lg: 'px-3 py-1.5 text-base gap-2',
};

const dotSizes: Record<BadgeSize, string> = {
  sm: 'w-1.5 h-1.5',
  md: 'w-2 h-2',
  lg: 'w-2.5 h-2.5',
};

export const Badge = forwardRef<HTMLSpanElement, BadgeProps>(
  (
    {
      variant = 'neutral',
      size = 'md',
      dot = false,
      pulse = false,
      icon,
      className,
      children,
      ...props
    },
    ref
  ) => {
    return (
      <span
        ref={ref}
        className={cn(
          'inline-flex items-center font-medium rounded-full border',
          variantStyles[variant],
          sizeStyles[size],
          className
        )}
        {...props}
      >
        {/* Dot indicator */}
        {dot && (
          <span className="relative flex">
            <span
              className={cn(
                'rounded-full',
                dotColors[variant],
                dotSizes[size]
              )}
            />
            {pulse && (
              <motion.span
                className={cn(
                  'absolute inset-0 rounded-full',
                  dotColors[variant],
                  'opacity-75'
                )}
                animate={{
                  scale: [1, 1.5, 1],
                  opacity: [0.75, 0, 0.75],
                }}
                transition={{
                  duration: 1.5,
                  repeat: Infinity,
                  ease: 'easeInOut',
                }}
              />
            )}
          </span>
        )}

        {/* Icon */}
        {icon && !dot && (
          <span className="flex-shrink-0">{icon}</span>
        )}

        {/* Text */}
        {children}
      </span>
    );
  }
);

Badge.displayName = 'Badge';

// Status Badge - Convenience component for common status indicators
export interface StatusBadgeProps extends Omit<BadgeProps, 'variant'> {
  status: 'online' | 'offline' | 'busy' | 'away' | 'pending' | 'active' | 'inactive';
}

const statusConfig: Record<StatusBadgeProps['status'], { variant: BadgeVariant; label: string }> = {
  online: { variant: 'success', label: 'Online' },
  offline: { variant: 'neutral', label: 'Offline' },
  busy: { variant: 'error', label: 'Busy' },
  away: { variant: 'warning', label: 'Away' },
  pending: { variant: 'warning', label: 'Pending' },
  active: { variant: 'success', label: 'Active' },
  inactive: { variant: 'neutral', label: 'Inactive' },
};

export const StatusBadge = forwardRef<HTMLSpanElement, StatusBadgeProps>(
  ({ status, children, ...props }, ref) => {
    const config = statusConfig[status];
    return (
      <Badge ref={ref} variant={config.variant} dot pulse={status === 'online'} {...props}>
        {children || config.label}
      </Badge>
    );
  }
);

StatusBadge.displayName = 'StatusBadge';

// Count Badge - For notification counts
export interface CountBadgeProps extends Omit<BadgeProps, 'children' | 'dot'> {
  count: number;
  max?: number;
  showZero?: boolean;
}

export const CountBadge = forwardRef<HTMLSpanElement, CountBadgeProps>(
  ({ count, max = 99, showZero = false, variant = 'error', size = 'sm', ...props }, ref) => {
    if (count === 0 && !showZero) return null;

    const displayCount = count > max ? `${max}+` : count.toString();

    return (
      <Badge
        ref={ref}
        variant={variant}
        size={size}
        className="min-w-[1.25rem] justify-center px-1.5"
        {...props}
      >
        {displayCount}
      </Badge>
    );
  }
);

CountBadge.displayName = 'CountBadge';

export default Badge;
