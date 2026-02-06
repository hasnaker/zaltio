'use client';

import React, { useRef, useEffect, useCallback, ReactNode } from 'react';

/**
 * Focus Trap Component
 * 
 * Traps keyboard focus within a container (useful for modals, dropdowns).
 * Implements WCAG 2.1 focus management requirements.
 */

interface FocusTrapProps {
  children: ReactNode;
  active?: boolean;
  returnFocusOnDeactivate?: boolean;
  initialFocus?: React.RefObject<HTMLElement>;
  className?: string;
}

const FOCUSABLE_SELECTORS = [
  'a[href]',
  'button:not([disabled])',
  'input:not([disabled])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
  '[contenteditable="true"]',
].join(', ');

export function FocusTrap({
  children,
  active = true,
  returnFocusOnDeactivate = true,
  initialFocus,
  className = '',
}: FocusTrapProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const previousActiveElement = useRef<HTMLElement | null>(null);

  // Get all focusable elements within container
  const getFocusableElements = useCallback(() => {
    if (!containerRef.current) return [];
    return Array.from(
      containerRef.current.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTORS)
    ).filter((el) => el.offsetParent !== null); // Filter out hidden elements
  }, []);

  // Handle tab key navigation
  const handleKeyDown = useCallback(
    (event: KeyboardEvent) => {
      if (!active || event.key !== 'Tab') return;

      const focusableElements = getFocusableElements();
      if (focusableElements.length === 0) return;

      const firstElement = focusableElements[0];
      const lastElement = focusableElements[focusableElements.length - 1];

      // Shift + Tab on first element -> go to last
      if (event.shiftKey && document.activeElement === firstElement) {
        event.preventDefault();
        lastElement.focus();
      }
      // Tab on last element -> go to first
      else if (!event.shiftKey && document.activeElement === lastElement) {
        event.preventDefault();
        firstElement.focus();
      }
    },
    [active, getFocusableElements]
  );

  // Set initial focus when activated
  useEffect(() => {
    if (!active) return;

    // Store current active element
    previousActiveElement.current = document.activeElement as HTMLElement;

    // Set initial focus
    if (initialFocus?.current) {
      initialFocus.current.focus();
    } else {
      const focusableElements = getFocusableElements();
      if (focusableElements.length > 0) {
        focusableElements[0].focus();
      }
    }

    // Add keydown listener
    document.addEventListener('keydown', handleKeyDown);

    return () => {
      document.removeEventListener('keydown', handleKeyDown);

      // Return focus on deactivate
      if (returnFocusOnDeactivate && previousActiveElement.current) {
        previousActiveElement.current.focus();
      }
    };
  }, [active, initialFocus, getFocusableElements, handleKeyDown, returnFocusOnDeactivate]);

  return (
    <div ref={containerRef} className={className}>
      {children}
    </div>
  );
}

export default FocusTrap;
