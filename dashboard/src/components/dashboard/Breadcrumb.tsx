'use client';

import React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';

export interface BreadcrumbItem {
  label: string;
  href: string;
}

export interface BreadcrumbProps {
  items?: BreadcrumbItem[];
  className?: string;
}

/**
 * Breadcrumb Component
 * 
 * A dynamic breadcrumb navigation component that parses the current path
 * and provides link navigation.
 * 
 * Requirements: 4.6
 */
export function Breadcrumb({ items, className = '' }: BreadcrumbProps) {
  const pathname = usePathname();

  // Generate breadcrumb items from pathname if not provided
  const breadcrumbItems: BreadcrumbItem[] = items || generateBreadcrumbsFromPath(pathname);

  return (
    <nav
      aria-label="Breadcrumb"
      className={`flex items-center space-x-2 text-sm ${className}`}
    >
      {/* Home Icon */}
      <Link
        href="/dashboard"
        className="
          text-nexus-text-muted hover:text-nexus-glow-cyan
          transition-colors duration-200
        "
        aria-label="Dashboard Home"
      >
        <svg
          className="w-4 h-4"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"
          />
        </svg>
      </Link>

      {breadcrumbItems.map((item, index) => {
        const isLast = index === breadcrumbItems.length - 1;

        return (
          <React.Fragment key={item.href}>
            {/* Separator */}
            <svg
              className="w-4 h-4 text-nexus-text-muted"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M9 5l7 7-7 7"
              />
            </svg>

            {/* Breadcrumb Item */}
            {isLast ? (
              <span
                className="text-nexus-text-primary font-medium"
                aria-current="page"
              >
                {item.label}
              </span>
            ) : (
              <Link
                href={item.href}
                className="
                  text-nexus-text-muted hover:text-nexus-glow-cyan
                  transition-colors duration-200
                "
              >
                {item.label}
              </Link>
            )}
          </React.Fragment>
        );
      })}
    </nav>
  );
}

/**
 * Generate breadcrumb items from a pathname
 */
function generateBreadcrumbsFromPath(pathname: string): BreadcrumbItem[] {
  // Remove leading slash and split by /
  const segments = pathname.replace(/^\//, '').split('/').filter(Boolean);
  
  // Skip 'dashboard' as it's the home
  const relevantSegments = segments.slice(1);
  
  if (relevantSegments.length === 0) {
    return [];
  }

  const items: BreadcrumbItem[] = [];
  let currentPath = '/dashboard';

  for (const segment of relevantSegments) {
    currentPath += `/${segment}`;
    
    // Format the label (capitalize, replace hyphens with spaces)
    const label = formatSegmentLabel(segment);
    
    items.push({
      label,
      href: currentPath,
    });
  }

  return items;
}

/**
 * Format a URL segment into a readable label
 */
function formatSegmentLabel(segment: string): string {
  // Check if it's a UUID or ID (skip formatting)
  if (isUUID(segment) || isNumericId(segment)) {
    return 'Details';
  }

  // Replace hyphens and underscores with spaces, capitalize each word
  return segment
    .replace(/[-_]/g, ' ')
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

/**
 * Check if a string is a UUID
 */
function isUUID(str: string): boolean {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  return uuidRegex.test(str);
}

/**
 * Check if a string is a numeric ID
 */
function isNumericId(str: string): boolean {
  return /^\d+$/.test(str);
}

export default Breadcrumb;
