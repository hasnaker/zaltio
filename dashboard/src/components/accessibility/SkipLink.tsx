'use client';

import { cn } from '@/lib/utils';

interface SkipLinkProps {
  href?: string;
  children?: React.ReactNode;
  className?: string;
}

/**
 * SkipLink component for keyboard navigation
 * Allows users to skip to main content
 */
export function SkipLink({ 
  href = '#main-content', 
  children = 'Skip to main content',
  className 
}: SkipLinkProps) {
  return (
    <a
      href={href}
      className={cn(
        'sr-only focus:not-sr-only',
        'focus:fixed focus:top-4 focus:left-4 focus:z-[100]',
        'focus:px-4 focus:py-2 focus:bg-primary focus:text-white',
        'focus:rounded-lg focus:shadow-lg focus:outline-none',
        'focus:ring-2 focus:ring-white focus:ring-offset-2 focus:ring-offset-primary',
        className
      )}
    >
      {children}
    </a>
  );
}

export default SkipLink;
