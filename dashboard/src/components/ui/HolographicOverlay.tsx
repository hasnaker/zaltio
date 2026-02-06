'use client';

import React from 'react';

export type HolographicVariant = 'default' | 'subtle' | 'intense' | 'border';

export interface HolographicOverlayProps {
  variant?: HolographicVariant;
  animated?: boolean;
  className?: string;
  children?: React.ReactNode;
}

/**
 * HolographicOverlay Component
 * 
 * A holographic gradient overlay utility that creates iridescent,
 * multi-color gradient effects for cards and panels.
 * 
 * Requirements: 1.5
 */
export function HolographicOverlay({
  variant = 'default',
  animated = false,
  className = '',
  children,
}: HolographicOverlayProps) {
  const variantStyles: Record<HolographicVariant, string> = {
    default: 'bg-nexus-holographic',
    subtle: 'bg-gradient-to-br from-nexus-glow-cyan/5 via-nexus-glow-purple/5 to-nexus-glow-pink/5',
    intense: 'bg-gradient-to-br from-nexus-glow-cyan/20 via-nexus-glow-purple/20 to-nexus-glow-pink/20',
    border: '',
  };

  const animationClass = animated ? 'animate-neural-flow bg-[length:200%_200%]' : '';

  if (variant === 'border') {
    return (
      <div
        className={`relative ${className}`}
        data-variant={variant}
        data-animated={animated}
      >
        {/* Holographic border effect */}
        <div
          className={`absolute -inset-[1px] rounded-xl bg-gradient-to-r from-nexus-glow-cyan via-nexus-glow-purple to-nexus-glow-pink opacity-50 blur-sm ${animationClass}`}
          aria-hidden="true"
        />
        <div
          className={`absolute -inset-[1px] rounded-xl bg-gradient-to-r from-nexus-glow-cyan via-nexus-glow-purple to-nexus-glow-pink opacity-30 ${animationClass}`}
          aria-hidden="true"
        />
        {/* Content container */}
        <div className="relative bg-nexus-cosmic-nebula rounded-xl">
          {children}
        </div>
      </div>
    );
  }

  return (
    <div
      className={`absolute inset-0 pointer-events-none ${variantStyles[variant]} ${animationClass} ${className}`}
      data-variant={variant}
      data-animated={animated}
      aria-hidden="true"
    >
      {children}
    </div>
  );
}

/**
 * Holographic gradient CSS utility classes
 * These can be used directly in Tailwind classes
 */
export const holographicGradients = {
  // Full holographic gradient
  full: 'bg-gradient-to-br from-nexus-glow-cyan/10 via-nexus-glow-purple/10 to-nexus-glow-pink/10',
  
  // Subtle holographic gradient
  subtle: 'bg-gradient-to-br from-nexus-glow-cyan/5 via-nexus-glow-purple/5 to-nexus-glow-pink/5',
  
  // Intense holographic gradient
  intense: 'bg-gradient-to-br from-nexus-glow-cyan/20 via-nexus-glow-purple/20 to-nexus-glow-pink/20',
  
  // Border gradient (for use with border-image or pseudo-elements)
  border: 'bg-gradient-to-r from-nexus-glow-cyan via-nexus-glow-purple to-nexus-glow-pink',
  
  // Animated holographic
  animated: 'bg-gradient-to-br from-nexus-glow-cyan/10 via-nexus-glow-purple/10 to-nexus-glow-pink/10 animate-neural-flow bg-[length:200%_200%]',
} as const;

/**
 * Helper function to get holographic gradient class
 */
export function getHolographicClass(
  variant: keyof typeof holographicGradients = 'full',
  animated = false
): string {
  const baseClass = holographicGradients[variant];
  return animated && variant !== 'animated'
    ? `${baseClass} animate-neural-flow bg-[length:200%_200%]`
    : baseClass;
}

export default HolographicOverlay;
