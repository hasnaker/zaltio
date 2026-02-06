'use client';

import React from 'react';

export type SkeletonVariant = 'text' | 'circular' | 'rectangular' | 'card' | 'avatar' | 'button';
export type SkeletonSize = 'sm' | 'md' | 'lg' | 'xl' | 'full';

export interface SkeletonProps {
  variant?: SkeletonVariant;
  size?: SkeletonSize;
  width?: string | number;
  height?: string | number;
  className?: string;
  animated?: boolean;
  count?: number;
}

/**
 * Skeleton Component
 * 
 * A skeleton loader component with shimmer animation for loading states.
 * Supports multiple variants and sizes for different use cases.
 * 
 * Requirements: 5.6
 */
export function Skeleton({
  variant = 'rectangular',
  size = 'md',
  width,
  height,
  className = '',
  animated = true,
  count = 1,
}: SkeletonProps) {
  const baseClasses = 'bg-nexus-cosmic-nebula/60 relative overflow-hidden';
  
  const shimmerClasses = animated
    ? 'before:absolute before:inset-0 before:-translate-x-full before:animate-shimmer before:bg-gradient-to-r before:from-transparent before:via-white/10 before:to-transparent'
    : '';

  const variantClasses: Record<SkeletonVariant, string> = {
    text: 'rounded',
    circular: 'rounded-full',
    rectangular: 'rounded-lg',
    card: 'rounded-xl',
    avatar: 'rounded-full',
    button: 'rounded-lg',
  };

  const sizeStyles: Record<SkeletonVariant, Record<SkeletonSize, { width: string; height: string }>> = {
    text: {
      sm: { width: '60%', height: '0.75rem' },
      md: { width: '80%', height: '1rem' },
      lg: { width: '100%', height: '1.25rem' },
      xl: { width: '100%', height: '1.5rem' },
      full: { width: '100%', height: '1rem' },
    },
    circular: {
      sm: { width: '1.5rem', height: '1.5rem' },
      md: { width: '2.5rem', height: '2.5rem' },
      lg: { width: '4rem', height: '4rem' },
      xl: { width: '6rem', height: '6rem' },
      full: { width: '100%', height: '100%' },
    },
    rectangular: {
      sm: { width: '100%', height: '2rem' },
      md: { width: '100%', height: '4rem' },
      lg: { width: '100%', height: '8rem' },
      xl: { width: '100%', height: '12rem' },
      full: { width: '100%', height: '100%' },
    },
    card: {
      sm: { width: '100%', height: '6rem' },
      md: { width: '100%', height: '10rem' },
      lg: { width: '100%', height: '16rem' },
      xl: { width: '100%', height: '20rem' },
      full: { width: '100%', height: '100%' },
    },
    avatar: {
      sm: { width: '2rem', height: '2rem' },
      md: { width: '3rem', height: '3rem' },
      lg: { width: '4rem', height: '4rem' },
      xl: { width: '6rem', height: '6rem' },
      full: { width: '100%', height: '100%' },
    },
    button: {
      sm: { width: '4rem', height: '1.75rem' },
      md: { width: '6rem', height: '2.25rem' },
      lg: { width: '8rem', height: '2.75rem' },
      xl: { width: '10rem', height: '3.25rem' },
      full: { width: '100%', height: '2.5rem' },
    },
  };

  const defaultSize = sizeStyles[variant][size];
  
  const style: React.CSSProperties = {
    width: width ?? defaultSize.width,
    height: height ?? defaultSize.height,
  };

  const classes = [
    baseClasses,
    shimmerClasses,
    variantClasses[variant],
    className,
  ].filter(Boolean).join(' ');

  const skeletons = Array.from({ length: count }, (_, index) => (
    <div
      key={index}
      className={classes}
      style={style}
      data-testid="skeleton-loader"
      data-variant={variant}
      data-size={size}
      data-animated={animated}
      role="status"
      aria-label="Loading..."
    />
  ));

  if (count === 1) {
    return skeletons[0];
  }

  return (
    <div className="space-y-2">
      {skeletons}
    </div>
  );
}

/**
 * SkeletonText - Convenience component for text skeletons
 */
export function SkeletonText({
  lines = 3,
  className = '',
  animated = true,
}: {
  lines?: number;
  className?: string;
  animated?: boolean;
}) {
  return (
    <div className={`space-y-2 ${className}`}>
      {Array.from({ length: lines }, (_, index) => (
        <Skeleton
          key={index}
          variant="text"
          size={index === lines - 1 ? 'sm' : 'md'}
          animated={animated}
        />
      ))}
    </div>
  );
}

/**
 * SkeletonCard - Convenience component for card skeletons
 */
export function SkeletonCard({
  className = '',
  animated = true,
}: {
  className?: string;
  animated?: boolean;
}) {
  return (
    <div className={`p-4 rounded-xl bg-nexus-cosmic-nebula/40 border border-white/10 ${className}`}>
      <div className="flex items-center space-x-4 mb-4">
        <Skeleton variant="avatar" size="md" animated={animated} />
        <div className="flex-1 space-y-2">
          <Skeleton variant="text" size="md" width="60%" animated={animated} />
          <Skeleton variant="text" size="sm" width="40%" animated={animated} />
        </div>
      </div>
      <Skeleton variant="rectangular" size="md" animated={animated} />
      <div className="mt-4 flex justify-end space-x-2">
        <Skeleton variant="button" size="sm" animated={animated} />
        <Skeleton variant="button" size="sm" animated={animated} />
      </div>
    </div>
  );
}

/**
 * SkeletonStatCard - Convenience component for stat card skeletons
 */
export function SkeletonStatCard({
  className = '',
  animated = true,
}: {
  className?: string;
  animated?: boolean;
}) {
  return (
    <div 
      className={`p-6 rounded-xl bg-nexus-cosmic-nebula/40 border border-white/10 ${className}`}
      data-testid="skeleton-loader"
    >
      <div className="flex items-center justify-between mb-4">
        <Skeleton variant="text" size="sm" width="40%" animated={animated} />
        <Skeleton variant="circular" size="sm" animated={animated} />
      </div>
      <Skeleton variant="text" size="xl" width="60%" animated={animated} />
      <div className="mt-2">
        <Skeleton variant="text" size="sm" width="30%" animated={animated} />
      </div>
    </div>
  );
}

export default Skeleton;
