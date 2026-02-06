'use client';

import React from 'react';

export type GlassCardVariant = 'default' | 'elevated' | 'bordered';
export type GlassCardGlow = 'none' | 'cyan' | 'purple' | 'pink';

export interface GlassCardProps {
  children: React.ReactNode;
  variant?: GlassCardVariant;
  glow?: GlassCardGlow;
  className?: string;
}

/**
 * GlassCard Component
 * 
 * A glassmorphism card component with backdrop-blur and subtle borders.
 * Supports multiple variants and glow effects.
 * 
 * Requirements: 1.6, 1.5
 */
export function GlassCard({
  children,
  variant = 'default',
  glow = 'none',
  className = '',
}: GlassCardProps) {
  const baseClasses = 'rounded-xl backdrop-blur-md';
  
  const variantClasses: Record<GlassCardVariant, string> = {
    default: 'bg-nexus-cosmic-nebula/40 border border-white/10',
    elevated: 'bg-nexus-cosmic-nebula/60 border border-white/10 shadow-elevated',
    bordered: 'bg-nexus-cosmic-nebula/30 border-2 border-white/20',
  };
  
  const glowClasses: Record<GlassCardGlow, string> = {
    none: '',
    cyan: 'shadow-glow-cyan hover:shadow-glow-cyan-lg transition-shadow duration-300',
    purple: 'shadow-glow-purple hover:shadow-glow-purple-lg transition-shadow duration-300',
    pink: 'shadow-glow-pink hover:shadow-glow-pink-lg transition-shadow duration-300',
  };
  
  const classes = [
    baseClasses,
    variantClasses[variant],
    glowClasses[glow],
    className,
  ].filter(Boolean).join(' ');
  
  return (
    <div className={classes} data-variant={variant} data-glow={glow}>
      {children}
    </div>
  );
}

export default GlassCard;
