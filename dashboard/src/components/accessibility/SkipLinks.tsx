'use client';

import React from 'react';

/**
 * Skip Links Component
 * 
 * Provides keyboard-accessible skip links for screen reader users
 * to bypass navigation and jump directly to main content.
 * 
 * Accessibility Requirements:
 * - Visible on focus
 * - High contrast colors
 * - Clear focus indicators
 */

interface SkipLink {
  href: string;
  label: string;
}

const defaultLinks: SkipLink[] = [
  { href: '#main-content', label: 'Skip to main content' },
  { href: '#navigation', label: 'Skip to navigation' },
  { href: '#footer', label: 'Skip to footer' },
];

interface SkipLinksProps {
  links?: SkipLink[];
}

export function SkipLinks({ links = defaultLinks }: SkipLinksProps) {
  return (
    <div className="skip-links">
      {links.map((link) => (
        <a
          key={link.href}
          href={link.href}
          className="sr-only focus:not-sr-only focus:absolute focus:top-4 focus:left-4 focus:z-[9999]
                     focus:px-4 focus:py-2 focus:bg-primary focus:text-white focus:rounded-lg
                     focus:font-semibold focus:shadow-lg focus:outline-none focus:ring-2 
                     focus:ring-white focus:ring-offset-2 focus:ring-offset-primary
                     transition-all duration-200"
        >
          {link.label}
        </a>
      ))}
    </div>
  );
}

export default SkipLinks;
