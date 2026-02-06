'use client';

import { useEffect, useRef } from 'react';
import { trackScrollDepth } from '@/lib/analytics';

interface ScrollTrackerProps {
  pagePath: string;
  thresholds?: number[];
}

/**
 * ScrollTracker component for tracking scroll depth analytics
 * Tracks when users scroll past certain percentage thresholds
 */
export function ScrollTracker({ 
  pagePath, 
  thresholds = [25, 50, 75, 100] 
}: ScrollTrackerProps) {
  const trackedThresholds = useRef<Set<number>>(new Set());

  useEffect(() => {
    // Reset tracked thresholds on page change
    trackedThresholds.current = new Set();

    const handleScroll = () => {
      const scrollHeight = document.documentElement.scrollHeight - window.innerHeight;
      if (scrollHeight <= 0) return;

      const scrollPercentage = Math.round((window.scrollY / scrollHeight) * 100);

      thresholds.forEach((threshold) => {
        if (
          scrollPercentage >= threshold && 
          !trackedThresholds.current.has(threshold)
        ) {
          trackedThresholds.current.add(threshold);
          trackScrollDepth(threshold, pagePath);
        }
      });
    };

    // Throttle scroll handler
    let ticking = false;
    const throttledScroll = () => {
      if (!ticking) {
        window.requestAnimationFrame(() => {
          handleScroll();
          ticking = false;
        });
        ticking = true;
      }
    };

    window.addEventListener('scroll', throttledScroll, { passive: true });
    
    // Check initial scroll position
    handleScroll();

    return () => {
      window.removeEventListener('scroll', throttledScroll);
    };
  }, [pagePath, thresholds]);

  return null;
}

export default ScrollTracker;
