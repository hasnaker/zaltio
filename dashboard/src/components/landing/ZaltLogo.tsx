'use client';

import React from 'react';
import Image from 'next/image';

interface ZaltLogoProps {
  variant?: 'full' | 'mascot';
  size?: 'xs' | 'sm' | 'md' | 'lg' | 'xl' | '2xl';
  className?: string;
}

// Height-based sizing (logo is vertical 370x513)
const sizeMap = {
  xs: 'h-6',
  sm: 'h-8',
  md: 'h-12',
  lg: 'h-16',
  xl: 'h-20',
  '2xl': 'h-28',
};

const mascotSizeMap = {
  xs: 24,
  sm: 32,
  md: 40,
  lg: 56,
  xl: 72,
  '2xl': 96,
};

export function ZaltLogo({ variant = 'full', size = 'md', className = '' }: ZaltLogoProps) {
  if (variant === 'mascot') {
    const mascotSize = mascotSizeMap[size];
    return (
      <Image
        src="/zalt-logo.svg"
        alt="Zalt"
        width={mascotSize}
        height={mascotSize}
        className={className}
        priority
      />
    );
  }

  // Full logo (vertical)
  return (
    <Image
      src="/zalt-full-logo.svg"
      alt="Zalt"
      width={80}
      height={111}
      className={`${sizeMap[size]} w-auto ${className}`}
      priority
    />
  );
}

// Loading spinner with mascot
export function ZaltLoader({ size = 'md' }: { size?: 'sm' | 'md' | 'lg' }) {
  return (
    <div className="flex items-center justify-center">
      <div className="animate-pulse">
        <ZaltLogo variant="mascot" size={size} />
      </div>
    </div>
  );
}

export default ZaltLogo;
